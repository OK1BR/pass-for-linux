/* window.c — the main window, M1 (docs/SPEC.md §9).
 *
 * AdwNavigationSplitView: store tree in the sidebar, one entry on the
 * right. Read-only in M1 — no writes anywhere. The sidebar model copies
 * names out of the engine's scan (names are cleartext on disk, §2.1), so
 * a rescan can free the old tree without racing the widgets. Decryption
 * runs on a worker thread — the first call can sit in the agent's
 * pinentry indefinitely — with an epoch counter so a stale result never
 * lands on a newer selection.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "window.h"

#include <string.h>

#include "crypto.h"
#include "entry-edit.h"
#include "entry-view.h"
#include "entry.h"
#include "history.h"
#include "recipient-view.h"
#include "store.h"
#include "vcs.h"

#define SEARCH_DEBOUNCE_MS 250

/* --- sidebar item: a thin GObject copy of one PassflNode ----------------- */

#define PASSFL_TYPE_ITEM (passfl_item_get_type ())
G_DECLARE_FINAL_TYPE (PassflItem, passfl_item, PASSFL, ITEM, GObject)

struct _PassflItem {
  GObject parent_instance;
  char *name;            /* basename for the tree label */
  char *rel;             /* entry name / directory path */
  gboolean is_dir;
  gboolean is_symlink;
  GListStore *children;  /* PassflItem; NULL for entries */
};

G_DEFINE_FINAL_TYPE (PassflItem, passfl_item, G_TYPE_OBJECT)

static void
passfl_item_finalize (GObject *obj)
{
  PassflItem *self = PASSFL_ITEM (obj);

  g_free (self->name);
  g_free (self->rel);
  g_clear_object (&self->children);
  G_OBJECT_CLASS (passfl_item_parent_class)->finalize (obj);
}

static void
passfl_item_class_init (PassflItemClass *klass)
{
  G_OBJECT_CLASS (klass)->finalize = passfl_item_finalize;
}

static void
passfl_item_init (PassflItem *self)
{
  (void) self;
}

static PassflItem *
passfl_item_new (const PassflNode *node)
{
  PassflItem *item = g_object_new (PASSFL_TYPE_ITEM, NULL);

  item->name = g_strdup (node->name);
  item->rel = g_strdup (node->rel);
  item->is_dir = node->kind == PASSFL_NODE_DIR;
  item->is_symlink = node->is_symlink;
  return item;
}

/* --- window --------------------------------------------------------------- */

struct _PassflWindow {
  AdwApplicationWindow parent_instance;

  char *store_dir;
  GListStore *roots;           /* top level of the tree, PassflItem */
  GPtrArray *flat;             /* every entry item, refs, for search */
  GtkListView *list;           /* one view, model swapped tree/search */
  GtkSelectionModel *tree_sel;
  GtkWidget *search;
  AdwToastOverlay *toasts;     /* NULL after dispose — thread sentinel */
  AdwNavigationPage *content_page;
  PassflEntryView *entry_view;
  PassflEntryEdit *entry_edit;
  GtkStack *content_stack;     /* "view" | "edit" */
  AdwWindowTitle *title;
  GtkWidget *btn_new, *btn_edit, *btn_delete, *btn_save, *btn_cancel;
  GtkWidget *btn_history;
  AdwBanner *reenc_banner;     /* §4.10 mismatch warning (M4) */
  char *pending_mvcp_new;      /* rename/copy waiting for overwrite confirm */
  gboolean pending_mvcp_copy;

  char *current_rel;           /* entry shown in the view, or NULL */
  gboolean editing;
  PassflSecBuf *edit_orig;     /* content at edit start — §4.6 unchanged? */
  gint64 edit_mtime;           /* on-disk mtime at edit start — §7.7 guard */
  char *pending_name;          /* save waiting for a confirm dialog */
  PassflSecBuf *pending_content;
  char *pending_message;       /* §6 commit message for the pending save */
  PassflWatch *watch;

  guint search_debounce_id;
  guint decrypt_epoch;         /* bumped per selection and per dispose */
};

G_DEFINE_FINAL_TYPE (PassflWindow, passfl_window, ADW_TYPE_APPLICATION_WINDOW)

static void rebuild_sidebar (PassflWindow *self);
static void open_entry (PassflWindow *self, const char *rel);
static void set_editing (PassflWindow *self, gboolean editing);
static void toast (PassflWindow *self, const char *fmt, ...);
static void do_write (PassflWindow *self, const char *name,
                      const PassflSecBuf *content, const char *message);

/* --- decrypt flow ---------------------------------------------------------- */

typedef struct {
  PassflWindow *self;          /* strong ref held for the job */
  guint epoch;
  char *rel;
  char *path;
  PassflSecBuf *buf;
  gboolean needs_reenc;        /* §4.10 sets disagree (M4) */
  GError *error;
} DecryptJob;

static gboolean
decrypt_done (gpointer data)
{
  DecryptJob *job = data;
  PassflWindow *self = job->self;

  if (self->toasts == NULL || job->epoch != self->decrypt_epoch)
    goto out; /* window gone or selection moved on — drop silently */

  if (job->buf == NULL)
    {
      if (!g_error_matches (job->error, PASSFL_CRYPTO_ERROR,
                            PASSFL_CRYPTO_ERROR_CANCELLED))
        passfl_entry_view_show_error (self->entry_view, job->rel,
                                      job->error != NULL
                                          ? job->error->message
                                          : "Decryption failed");
      else
        passfl_entry_view_show_placeholder (self->entry_view);
      goto out;
    }

  passfl_entry_view_show_entry (self->entry_view, job->rel,
                                passfl_entry_parse (job->buf->data,
                                                    job->buf->len));
  adw_navigation_page_set_title (self->content_page, job->rel);
  g_free (self->current_rel);
  self->current_rel = g_strdup (job->rel);
  gtk_widget_set_visible (self->btn_edit, TRUE);
  gtk_widget_set_visible (self->btn_delete, TRUE);
  gtk_widget_set_visible (self->btn_history, TRUE);
  adw_banner_set_revealed (self->reenc_banner, job->needs_reenc);

out:
  g_clear_pointer (&job->buf, passfl_secbuf_free);
  g_clear_error (&job->error);
  g_free (job->rel);
  g_free (job->path);
  g_object_unref (job->self);
  g_free (job);
  return G_SOURCE_REMOVE;
}

static gpointer
decrypt_thread (gpointer data)
{
  DecryptJob *job = data;

  job->buf = passfl_crypto_decrypt_file (job->path, &job->error);
  if (job->buf != NULL)
    passfl_store_entry_needs_reencrypt (job->self->store_dir, job->rel,
                                        &job->needs_reenc, NULL);
  g_idle_add (decrypt_done, job);
  return NULL;
}

static void
open_entry (PassflWindow *self, const char *rel)
{
  DecryptJob *job = g_new0 (DecryptJob, 1);

  self->decrypt_epoch++;
  job->self = g_object_ref (self);
  job->epoch = self->decrypt_epoch;
  job->rel = g_strdup (rel);
  job->path = g_strconcat (self->store_dir, "/", rel, ".gpg", NULL);
  g_thread_unref (g_thread_new ("passfl-decrypt", decrypt_thread, job));
}

/* --- selection -------------------------------------------------------------- */

static PassflItem *
selected_item (GtkSelectionModel *sel)
{
  GObject *obj = gtk_single_selection_get_selected_item (
      GTK_SINGLE_SELECTION (sel));

  if (obj == NULL)
    return NULL;
  if (GTK_IS_TREE_LIST_ROW (obj))
    {
      g_autoptr (GObject) inner =
          gtk_tree_list_row_get_item (GTK_TREE_LIST_ROW (obj));
      return PASSFL_ITEM (inner); /* borrowed: the row keeps it alive */
    }
  return PASSFL_ITEM (obj);
}

static void
on_selection_changed (PassflWindow *self, GParamSpec *pspec, gpointer sel)
{
  PassflItem *item = selected_item (GTK_SELECTION_MODEL (sel));

  (void) pspec;
  if (self->editing) /* finish or cancel the edit first */
    return;
  if (item == NULL || item->is_dir)
    return;
  if (self->current_rel != NULL && strcmp (item->rel, self->current_rel) == 0)
    return; /* already shown — e.g. focus reselecting after a rebuild */
  open_entry (self, item->rel);
}

/* --- sidebar model ---------------------------------------------------------- */

static GListStore *
build_items (PassflWindow *self, const PassflNode *dir)
{
  GListStore *store = g_list_store_new (PASSFL_TYPE_ITEM);

  for (guint i = 0; i < dir->children->len; i++)
    {
      const PassflNode *node = g_ptr_array_index (dir->children, i);
      PassflItem *item = passfl_item_new (node);

      if (node->kind == PASSFL_NODE_DIR)
        item->children = build_items (self, node);
      else
        g_ptr_array_add (self->flat, g_object_ref (item));
      g_list_store_append (store, item);
      g_object_unref (item);
    }
  return store;
}

static GListModel *
tree_create_children (gpointer obj, gpointer user_data)
{
  PassflItem *item = PASSFL_ITEM (obj);

  (void) user_data;
  if (item->children == NULL)
    return NULL;
  return G_LIST_MODEL (g_object_ref (item->children));
}

static const char *
item_icon (const PassflItem *item)
{
  if (item->is_dir)
    return "folder-symbolic";
  return item->is_symlink ? "emblem-symbolic-link"
                          : "dialog-password-symbolic";
}

/* Shared row body: icon + label, filled in bind. */
static GtkWidget *
row_body_new (void)
{
  GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
  GtkWidget *icon = gtk_image_new ();
  GtkWidget *label = gtk_label_new (NULL);

  gtk_label_set_xalign (GTK_LABEL (label), 0);
  gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_MIDDLE);
  gtk_box_append (GTK_BOX (box), icon);
  gtk_box_append (GTK_BOX (box), label);
  return box;
}

static void
row_body_bind (GtkWidget *box, const PassflItem *item, const char *text)
{
  GtkWidget *icon = gtk_widget_get_first_child (box);
  GtkWidget *label = gtk_widget_get_last_child (box);

  gtk_image_set_from_icon_name (GTK_IMAGE (icon), item_icon (item));
  gtk_label_set_text (GTK_LABEL (label), text);
}

static void
tree_row_setup (GtkListItemFactory *factory, GtkListItem *list_item,
                gpointer user_data)
{
  GtkWidget *expander = gtk_tree_expander_new ();

  (void) factory;
  (void) user_data;
  gtk_tree_expander_set_child (GTK_TREE_EXPANDER (expander), row_body_new ());
  gtk_list_item_set_child (list_item, expander);
}

static void
tree_row_bind (GtkListItemFactory *factory, GtkListItem *list_item,
               gpointer user_data)
{
  GtkTreeListRow *row = gtk_list_item_get_item (list_item);
  GtkWidget *expander = gtk_list_item_get_child (list_item);
  g_autoptr (GObject) obj = gtk_tree_list_row_get_item (row);
  PassflItem *item = PASSFL_ITEM (obj);

  (void) factory;
  (void) user_data;
  gtk_tree_expander_set_list_row (GTK_TREE_EXPANDER (expander), row);
  row_body_bind (gtk_tree_expander_get_child (GTK_TREE_EXPANDER (expander)),
                 item, item->name);
}

static void
flat_row_setup (GtkListItemFactory *factory, GtkListItem *list_item,
                gpointer user_data)
{
  (void) factory;
  (void) user_data;
  gtk_list_item_set_child (list_item, row_body_new ());
}

static void
flat_row_bind (GtkListItemFactory *factory, GtkListItem *list_item,
               gpointer user_data)
{
  PassflItem *item = gtk_list_item_get_item (list_item);

  (void) factory;
  (void) user_data;
  row_body_bind (gtk_list_item_get_child (list_item), item, item->rel);
}

static GtkSelectionModel *
make_selection (PassflWindow *self, GListModel *model)
{
  GtkSingleSelection *sel = gtk_single_selection_new (model);

  gtk_single_selection_set_autoselect (sel, FALSE);
  gtk_single_selection_set_can_unselect (sel, TRUE);
  gtk_single_selection_set_selected (sel, GTK_INVALID_LIST_POSITION);
  g_signal_connect_swapped (sel, "notify::selected-item",
                            G_CALLBACK (on_selection_changed), self);
  return GTK_SELECTION_MODEL (sel);
}

static void
show_tree (PassflWindow *self)
{
  GtkListItemFactory *factory = gtk_signal_list_item_factory_new ();

  g_signal_connect (factory, "setup", G_CALLBACK (tree_row_setup), self);
  g_signal_connect (factory, "bind", G_CALLBACK (tree_row_bind), self);

  GtkTreeListModel *tree = gtk_tree_list_model_new (
      G_LIST_MODEL (g_object_ref (self->roots)), FALSE, FALSE,
      tree_create_children, NULL, NULL);
  self->tree_sel = make_selection (self, G_LIST_MODEL (tree));
  gtk_list_view_set_factory (self->list, factory);
  gtk_list_view_set_model (self->list, self->tree_sel);
  g_object_unref (factory);
}

static void
show_search (PassflWindow *self, const char *needle)
{
  GtkListItemFactory *factory = gtk_signal_list_item_factory_new ();
  GListStore *matches = g_list_store_new (PASSFL_TYPE_ITEM);
  g_autofree char *folded = g_utf8_casefold (needle, -1);

  for (guint i = 0; i < self->flat->len; i++)
    {
      PassflItem *item = g_ptr_array_index (self->flat, i);
      g_autofree char *hay = g_utf8_casefold (item->rel, -1);

      if (strstr (hay, folded) != NULL)
        g_list_store_append (matches, item);
    }

  g_signal_connect (factory, "setup", G_CALLBACK (flat_row_setup), self);
  g_signal_connect (factory, "bind", G_CALLBACK (flat_row_bind), self);
  self->tree_sel = NULL; /* owned by the view; replaced below */
  gtk_list_view_set_factory (self->list, factory);
  gtk_list_view_set_model (self->list,
                           make_selection (self, G_LIST_MODEL (matches)));
  g_object_unref (factory);
}

static gboolean
search_apply (gpointer data)
{
  PassflWindow *self = data;
  const char *text =
      gtk_editable_get_text (GTK_EDITABLE (self->search));

  self->search_debounce_id = 0;
  if (text == NULL || *text == '\0')
    show_tree (self);
  else
    show_search (self, text);
  return G_SOURCE_REMOVE;
}

static void
on_search_changed (PassflWindow *self)
{
  g_clear_handle_id (&self->search_debounce_id, g_source_remove);
  self->search_debounce_id =
      g_timeout_add (SEARCH_DEBOUNCE_MS, search_apply, self);
}

static void
rebuild_sidebar (PassflWindow *self)
{
  GError *error = NULL;
  PassflNode *tree = passfl_store_scan (self->store_dir, &error);

  g_ptr_array_set_size (self->flat, 0);
  g_clear_object (&self->roots);

  if (tree == NULL)
    {
      self->roots = g_list_store_new (PASSFL_TYPE_ITEM);
      passfl_entry_view_show_error (self->entry_view, "No password store",
                                    error->message);
      g_error_free (error);
    }
  else
    {
      self->roots = build_items (self, tree);
      passfl_node_free (tree);
    }
  if (self->watch != NULL) /* new directories need monitors too */
    passfl_store_watch_rearm (self->watch);
  search_apply (self); /* re-shows tree or re-runs the active search */
}

/* --- edit flow (M2) ----------------------------------------------------------- */

static void
toast (PassflWindow *self, const char *fmt, ...)
{
  va_list ap;
  char *msg;

  if (self->toasts == NULL)
    return;
  va_start (ap, fmt);
  msg = g_strdup_vprintf (fmt, ap);
  va_end (ap);
  adw_toast_overlay_add_toast (self->toasts, adw_toast_new (msg));
  g_free (msg);
}

static void
set_editing (PassflWindow *self, gboolean editing)
{
  self->editing = editing;
  if (editing)
    adw_banner_set_revealed (self->reenc_banner, FALSE);
  gtk_stack_set_visible_child_name (self->content_stack,
                                    editing ? "edit" : "view");
  gtk_widget_set_visible (self->btn_save, editing);
  gtk_widget_set_visible (self->btn_cancel, editing);
  gtk_widget_set_visible (self->btn_edit,
                          !editing && self->current_rel != NULL);
  gtk_widget_set_visible (self->btn_delete,
                          !editing && self->current_rel != NULL);
  gtk_widget_set_visible (self->btn_history,
                          !editing && self->current_rel != NULL);
  gtk_widget_set_sensitive (self->btn_new, !editing);
  if (!editing)
    {
      /* keep focus away from the just-rebuilt list, whose focus row
       * would otherwise grab the selection (and the content pane) */
      gtk_widget_grab_focus (self->search);
      g_clear_pointer (&self->edit_orig, passfl_secbuf_free);
      g_clear_pointer (&self->pending_name, g_free);
      g_clear_pointer (&self->pending_content, passfl_secbuf_free);
      g_clear_pointer (&self->pending_message, g_free);
    }
}

static void
act_new (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;

  (void) action;
  (void) param;
  if (self->editing)
    return;
  passfl_entry_edit_begin (self->entry_edit, NULL, NULL);
  adw_navigation_page_set_title (self->content_page, "New entry");
  self->edit_mtime = -1;
  set_editing (self, TRUE);
}

static void
act_edit (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;
  PassflEntry *entry;

  (void) action;
  (void) param;
  if (self->editing || self->current_rel == NULL)
    return;
  entry = passfl_entry_view_steal_entry (self->entry_view);
  if (entry == NULL)
    return;
  self->edit_mtime = passfl_store_entry_mtime (self->store_dir,
                                               self->current_rel);
  passfl_entry_edit_begin (self->entry_edit, self->current_rel, entry);
  set_editing (self, TRUE);
  /* snapshot for the §4.6 "Password unchanged." short-circuit */
  self->edit_orig = passfl_entry_edit_content (self->entry_edit);
}

static void
act_cancel (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;
  gboolean was_new;

  (void) action;
  (void) param;
  if (!self->editing)
    return;
  was_new = passfl_entry_edit_is_new (self->entry_edit);
  set_editing (self, FALSE);
  if (!was_new && self->current_rel != NULL)
    open_entry (self, self->current_rel); /* the view gave its entry away */
  else
    {
      passfl_entry_view_show_placeholder (self->entry_view);
      adw_navigation_page_set_title (self->content_page, "Entry");
    }
}

/* One commit per operation (§6); a store without git is a no-op. A
 * failed commit is reported but the write stands, like in pass. */
static void
vcs_commit (PassflWindow *self, const char *name, const char *message)
{
  GError *error = NULL;
  g_autofree char *path =
      g_strconcat (self->store_dir, "/", name, ".gpg", NULL);
  PassflVcs *vcs = passfl_vcs_open (self->store_dir, path, &error);

  if (vcs == NULL)
    {
      if (error != NULL)
        {
          toast (self, "%s", error->message);
          g_error_free (error);
        }
      return;
    }
  if (!passfl_vcs_commit_file (vcs, path, message, &error))
    {
      toast (self, "Saved, but git commit failed: %s", error->message);
      g_error_free (error);
    }
  passfl_vcs_free (vcs);
}

static void
do_write (PassflWindow *self, const char *name,
          const PassflSecBuf *content, const char *message)
{
  GError *error = NULL;
  /* name may be self->pending_name, which set_editing frees — copy. */
  g_autofree char *name_copy = g_strdup (name);

  if (!passfl_store_write_entry (self->store_dir, name_copy, content->data,
                                 content->len, &error))
    {
      toast (self, "%s", error->message);
      g_error_free (error);
      return; /* stay in the editor — nothing was lost */
    }
  vcs_commit (self, name_copy, message);
  set_editing (self, FALSE);
  g_free (self->current_rel);
  self->current_rel = g_strdup (name_copy);
  rebuild_sidebar (self);
  open_entry (self, name_copy);
}

static void
on_confirm_save (AdwAlertDialog *dialog, GAsyncResult *result, gpointer data)
{
  PassflWindow *self = data;
  const char *response = adw_alert_dialog_choose_finish (dialog, result);

  if (self->toasts == NULL || !self->editing)
    return;
  if (strcmp (response, "overwrite") == 0 && self->pending_name != NULL)
    do_write (self, self->pending_name, self->pending_content,
              self->pending_message);
  g_clear_pointer (&self->pending_name, g_free);
  g_clear_pointer (&self->pending_content, passfl_secbuf_free);
  g_clear_pointer (&self->pending_message, g_free);
}

static void
confirm_save (PassflWindow *self, const char *heading, const char *body,
              const char *name, PassflSecBuf *content /* takes */,
              const char *message)
{
  AdwDialog *dlg = adw_alert_dialog_new (heading, NULL);

  g_clear_pointer (&self->pending_name, g_free);
  g_clear_pointer (&self->pending_content, passfl_secbuf_free);
  g_clear_pointer (&self->pending_message, g_free);
  self->pending_name = g_strdup (name);
  self->pending_content = content;
  self->pending_message = g_strdup (message);

  adw_alert_dialog_format_body (ADW_ALERT_DIALOG (dlg), "%s", body);
  adw_alert_dialog_add_responses (ADW_ALERT_DIALOG (dlg), "cancel",
                                  "Cancel", "overwrite", "Overwrite", NULL);
  adw_alert_dialog_set_response_appearance (ADW_ALERT_DIALOG (dlg),
                                            "overwrite",
                                            ADW_RESPONSE_DESTRUCTIVE);
  adw_alert_dialog_set_default_response (ADW_ALERT_DIALOG (dlg), "cancel");
  adw_alert_dialog_choose (ADW_ALERT_DIALOG (dlg), GTK_WIDGET (self), NULL,
                           (GAsyncReadyCallback) on_confirm_save, self);
}

static void
act_save (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;
  g_autofree char *name = NULL;
  PassflSecBuf *content;
  gboolean is_new;

  (void) action;
  (void) param;
  if (!self->editing)
    return;

  is_new = passfl_entry_edit_is_new (self->entry_edit);
  name = g_strdup (passfl_entry_edit_name (self->entry_edit));
  g_strstrip (name);
  if (*name == '\0')
    {
      toast (self, "The entry needs a name");
      return;
    }
  if (!passfl_entry_name_is_safe (name) || name[0] == '/' ||
      g_str_has_suffix (name, "/") || strstr (name, "//") != NULL)
    {
      toast (self, "Invalid entry name '%s'", name);
      return;
    }
  g_autofree char *message = is_new ? passfl_vcs_msg_insert (name)
                                    : passfl_vcs_msg_edit (name, TRUE);

  content = passfl_entry_edit_content (self->entry_edit);

  /* §4.6: byte-identical content means no write and no history churn. */
  if (!is_new && self->edit_orig != NULL &&
      content->len == self->edit_orig->len &&
      memcmp (content->data, self->edit_orig->data, content->len) == 0)
    {
      passfl_secbuf_free (content);
      toast (self, "Password unchanged.");
      set_editing (self, FALSE);
      open_entry (self, self->current_rel);
      return;
    }

  if (is_new && passfl_store_entry_exists (self->store_dir, name))
    {
      g_autofree char *body = g_strdup_printf (
          "An entry for %s already exists.", name);

      confirm_save (self, "Overwrite entry?", body, name, content,
                    message);
      return; /* §4.5: prompt before overwrite */
    }
  if (!is_new &&
      passfl_store_entry_mtime (self->store_dir, name) != self->edit_mtime)
    {
      g_autofree char *body = g_strdup_printf (
          "%s changed on disk while you were editing — probably the CLI "
          "or another machine via git. Overwrite that change?", name);

      confirm_save (self, "Entry changed on disk", body, name, content,
                    message);
      return; /* §7.7: never overwrite a concurrent change blindly */
    }

  do_write (self, name, content, message);
  passfl_secbuf_free (content);
}

static void
on_confirm_delete (AdwAlertDialog *dialog, GAsyncResult *result,
                   gpointer data)
{
  PassflWindow *self = data;
  const char *response = adw_alert_dialog_choose_finish (dialog, result);
  GError *error = NULL;

  if (self->toasts == NULL || self->current_rel == NULL ||
      strcmp (response, "delete") != 0)
    return;
  {
    g_autofree char *path = g_strconcat (self->store_dir, "/",
                                         self->current_rel, ".gpg", NULL);
    g_autofree char *message = passfl_vcs_msg_remove (self->current_rel);
    /* discover before the file and its pruned parents disappear */
    PassflVcs *vcs = passfl_vcs_open (self->store_dir, path, NULL);

    if (!passfl_store_delete_entry (self->store_dir, self->current_rel,
                                    &error))
      {
        toast (self, "%s", error->message);
        g_error_free (error);
        passfl_vcs_free (vcs);
        return;
      }
    if (vcs != NULL)
      {
        GError *git_error = NULL;

        if (!passfl_vcs_commit_file (vcs, path, message, &git_error))
          {
            toast (self, "Removed, but git commit failed: %s",
                   git_error->message);
            g_error_free (git_error);
          }
        passfl_vcs_free (vcs);
      }
  }
  g_clear_pointer (&self->current_rel, g_free);
  gtk_widget_set_visible (self->btn_edit, FALSE);
  gtk_widget_set_visible (self->btn_delete, FALSE);
  gtk_widget_set_visible (self->btn_history, FALSE);
  adw_banner_set_revealed (self->reenc_banner, FALSE);
  passfl_entry_view_show_placeholder (self->entry_view);
  adw_navigation_page_set_title (self->content_page, "Entry");
  rebuild_sidebar (self);
}

static void
act_delete (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;
  AdwDialog *dlg;

  (void) action;
  (void) param;
  if (self->editing || self->current_rel == NULL)
    return;
  dlg = adw_alert_dialog_new ("Delete entry?", NULL);
  adw_alert_dialog_format_body (ADW_ALERT_DIALOG (dlg),
                                "Remove %s from the store? There is no "
                                "undo until git history lands (M3).",
                                self->current_rel);
  adw_alert_dialog_add_responses (ADW_ALERT_DIALOG (dlg), "cancel",
                                  "Cancel", "delete", "Delete", NULL);
  adw_alert_dialog_set_response_appearance (ADW_ALERT_DIALOG (dlg),
                                            "delete",
                                            ADW_RESPONSE_DESTRUCTIVE);
  adw_alert_dialog_set_default_response (ADW_ALERT_DIALOG (dlg), "cancel");
  adw_alert_dialog_choose (ADW_ALERT_DIALOG (dlg), GTK_WIDGET (self), NULL,
                           (GAsyncReadyCallback) on_confirm_delete, self);
}

static void
on_history_restore (const char *rel, PassflSecBuf *content, gpointer data)
{
  PassflWindow *self = data;
  g_autofree char *message = passfl_vcs_msg_edit (rel, TRUE);
  GError *error = NULL;

  if (!passfl_store_write_entry (self->store_dir, rel, content->data,
                                 content->len, &error))
    {
      toast (self, "%s", error->message);
      g_error_free (error);
    }
  else
    {
      vcs_commit (self, rel, message);
      toast (self, "Restored %s", rel);
      rebuild_sidebar (self);
      open_entry (self, rel);
    }
  passfl_secbuf_free (content);
}

static void
act_history (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;
  AdwDialog *dlg;

  (void) action;
  (void) param;
  if (self->editing || self->current_rel == NULL)
    return;
  dlg = passfl_history_new (self->store_dir, self->current_rel,
                            on_history_restore, self);
  adw_dialog_present (dlg, GTK_WIDGET (self));
}

static void
on_recipients_reencrypted (guint n_changed, gpointer data)
{
  PassflWindow *self = data;

  toast (self, "Re-encrypted %u %s", n_changed,
         n_changed == 1 ? "entry" : "entries");
  rebuild_sidebar (self);
  if (self->current_rel != NULL)
    open_entry (self, self->current_rel);
}

static void act_recipients (GSimpleAction *action, GVariant *param,
                            gpointer data);

static void
act_recipients_from_banner (PassflWindow *self)
{
  act_recipients (NULL, NULL, self);
}

static void
act_recipients (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;
  AdwDialog *dlg;

  (void) action;
  (void) param;
  if (self->editing || self->current_rel == NULL)
    return;
  dlg = passfl_recipient_view_new (self->store_dir, self->current_rel,
                                   on_recipients_reencrypted, self);
  adw_dialog_present (dlg, GTK_WIDGET (self));
}

/* rename / duplicate — engine mv/cp with an overwrite confirm on EXISTS */

static void do_mvcp (PassflWindow *self, const char *new_name,
                     gboolean is_copy, gboolean force);

static void
on_mvcp_overwrite (AdwAlertDialog *dialog, GAsyncResult *result,
                   gpointer data)
{
  PassflWindow *self = data;
  const char *response = adw_alert_dialog_choose_finish (dialog, result);

  if (self->toasts == NULL || self->pending_mvcp_new == NULL ||
      self->current_rel == NULL)
    return;
  if (strcmp (response, "overwrite") == 0)
    {
      g_autofree char *target = g_steal_pointer (&self->pending_mvcp_new);

      do_mvcp (self, target, self->pending_mvcp_copy, TRUE);
    }
  else
    g_clear_pointer (&self->pending_mvcp_new, g_free);
}

static void
do_mvcp (PassflWindow *self, const char *new_name, gboolean is_copy,
         gboolean force)
{
  GError *error = NULL;
  gboolean ok = is_copy
      ? passfl_store_copy (self->store_dir, self->current_rel, new_name,
                           force, NULL, NULL, &error)
      : passfl_store_move (self->store_dir, self->current_rel, new_name,
                           force, NULL, NULL, &error);

  if (!ok && g_error_matches (error, PASSFL_STORE_ERROR,
                              PASSFL_STORE_ERROR_EXISTS))
    {
      AdwDialog *dlg = adw_alert_dialog_new ("Overwrite entry?", NULL);

      g_clear_error (&error);
      g_free (self->pending_mvcp_new);
      self->pending_mvcp_new = g_strdup (new_name);
      self->pending_mvcp_copy = is_copy;
      adw_alert_dialog_format_body (ADW_ALERT_DIALOG (dlg),
                                    "An entry for %s already exists.",
                                    new_name);
      adw_alert_dialog_add_responses (ADW_ALERT_DIALOG (dlg), "cancel",
                                      "Cancel", "overwrite", "Overwrite",
                                      NULL);
      adw_alert_dialog_set_response_appearance (ADW_ALERT_DIALOG (dlg),
                                                "overwrite",
                                                ADW_RESPONSE_DESTRUCTIVE);
      adw_alert_dialog_set_default_response (ADW_ALERT_DIALOG (dlg),
                                             "cancel");
      adw_alert_dialog_choose (ADW_ALERT_DIALOG (dlg), GTK_WIDGET (self),
                               NULL,
                               (GAsyncReadyCallback) on_mvcp_overwrite,
                               self);
      return;
    }
  if (!ok)
    {
      toast (self, "%s", error->message);
      g_error_free (error);
      return;
    }
  toast (self, "%s %s", is_copy ? "Copied to" : "Renamed to", new_name);
  g_free (self->current_rel);
  self->current_rel = g_strdup (new_name);
  rebuild_sidebar (self);
  open_entry (self, new_name);
}

static void
on_mvcp_response (AdwAlertDialog *dialog, GAsyncResult *result,
                  gpointer data)
{
  PassflWindow *self = data;
  const char *response = adw_alert_dialog_choose_finish (dialog, result);
  GtkWidget *entry;
  g_autofree char *name = NULL;
  gboolean is_copy;

  if (self->toasts == NULL || strcmp (response, "ok") != 0 ||
      self->current_rel == NULL)
    return;
  entry = adw_alert_dialog_get_extra_child (dialog);
  is_copy = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (dialog),
                                                "passfl-is-copy"));
  name = g_strdup (gtk_editable_get_text (GTK_EDITABLE (entry)));
  g_strstrip (name);
  if (*name == '\0' || !passfl_entry_name_is_safe (name) ||
      name[0] == '/' || strstr (name, "//") != NULL)
    {
      toast (self, "Invalid entry name '%s'", name);
      return;
    }
  if (strcmp (name, self->current_rel) == 0)
    return;
  do_mvcp (self, name, is_copy, FALSE);
}

static void
mvcp_dialog (PassflWindow *self, gboolean is_copy)
{
  AdwDialog *dlg;
  GtkWidget *entry;

  if (self->editing || self->current_rel == NULL)
    return;
  dlg = adw_alert_dialog_new (is_copy ? "Duplicate entry" : "Rename entry",
                              NULL);
  adw_alert_dialog_format_body (ADW_ALERT_DIALOG (dlg), "%s %s as:",
                                is_copy ? "Copy" : "Rename",
                                self->current_rel);
  entry = gtk_entry_new ();
  gtk_editable_set_text (GTK_EDITABLE (entry), self->current_rel);
  gtk_widget_add_css_class (entry, "monospace");
  adw_alert_dialog_set_extra_child (ADW_ALERT_DIALOG (dlg), entry);
  g_object_set_data (G_OBJECT (dlg), "passfl-is-copy",
                     GINT_TO_POINTER (is_copy));
  adw_alert_dialog_add_responses (ADW_ALERT_DIALOG (dlg), "cancel",
                                  "Cancel", "ok",
                                  is_copy ? "Duplicate" : "Rename", NULL);
  adw_alert_dialog_set_response_appearance (ADW_ALERT_DIALOG (dlg), "ok",
                                            ADW_RESPONSE_SUGGESTED);
  adw_alert_dialog_set_default_response (ADW_ALERT_DIALOG (dlg), "ok");
  adw_alert_dialog_choose (ADW_ALERT_DIALOG (dlg), GTK_WIDGET (self), NULL,
                           (GAsyncReadyCallback) on_mvcp_response, self);
}

static void
act_rename (GSimpleAction *action, GVariant *param, gpointer data)
{
  (void) action;
  (void) param;
  mvcp_dialog (data, FALSE);
}

static void
act_copy_entry (GSimpleAction *action, GVariant *param, gpointer data)
{
  (void) action;
  (void) param;
  mvcp_dialog (data, TRUE);
}

static void
on_store_changed (gpointer data)
{
  PassflWindow *self = data;

  rebuild_sidebar (self);
}

/* --- actions ----------------------------------------------------------------- */

static void
act_refresh (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;

  (void) action;
  (void) param;
  rebuild_sidebar (self);
}

static void
act_about (GSimpleAction *action, GVariant *param, gpointer data)
{
  PassflWindow *self = data;
  AdwDialog *dlg = adw_about_dialog_new ();
  g_autofree char *dbg = g_strdup_printf ("Store: %s", self->store_dir);

  (void) action;
  (void) param;
  adw_about_dialog_set_application_name (ADW_ABOUT_DIALOG (dlg),
                                         "Pass for Linux");
  adw_about_dialog_set_version (ADW_ABOUT_DIALOG (dlg), PASSFL_VERSION);
  adw_about_dialog_set_developer_name (ADW_ABOUT_DIALOG (dlg),
                                       "Richard Fakenberg, OK1BR");
  adw_about_dialog_set_license_type (ADW_ABOUT_DIALOG (dlg),
                                     GTK_LICENSE_GPL_3_0);
  adw_about_dialog_set_website (ADW_ABOUT_DIALOG (dlg),
                                "https://github.com/OK1BR/pass-for-linux");
  adw_about_dialog_set_debug_info (ADW_ABOUT_DIALOG (dlg), dbg);
  adw_dialog_present (dlg, GTK_WIDGET (self));
}

static const GActionEntry win_actions[] = {
  { .name = "refresh", .activate = act_refresh },
  { .name = "about", .activate = act_about },
  { .name = "new", .activate = act_new },
  { .name = "edit", .activate = act_edit },
  { .name = "delete", .activate = act_delete },
  { .name = "save", .activate = act_save },
  { .name = "cancel", .activate = act_cancel },
  { .name = "history", .activate = act_history },
  { .name = "recipients", .activate = act_recipients },
  { .name = "rename", .activate = act_rename },
  { .name = "copy-entry", .activate = act_copy_entry },
};

static gboolean
on_main_key (GtkEventControllerKey *ctl, guint keyval, guint keycode,
             GdkModifierType state, gpointer data)
{
  PassflWindow *self = data;

  (void) ctl;
  (void) keycode;
  if (adw_application_window_get_visible_dialog (
          ADW_APPLICATION_WINDOW (self)))
    return FALSE;
  if (self->editing && (state & GDK_CONTROL_MASK) != 0 &&
      keyval == GDK_KEY_s)
    {
      g_action_group_activate_action (G_ACTION_GROUP (self), "save", NULL);
      return TRUE;
    }
  if (state & (GDK_CONTROL_MASK | GDK_ALT_MASK | GDK_SUPER_MASK))
    return FALSE;
  if (self->editing && keyval == GDK_KEY_Escape)
    {
      g_action_group_activate_action (G_ACTION_GROUP (self), "cancel",
                                      NULL);
      return TRUE;
    }
  if (keyval == GDK_KEY_F5)
    {
      rebuild_sidebar (self);
      return TRUE;
    }
  return FALSE;
}

/* --- construction -------------------------------------------------------------- */

static GtkWidget *
build_sidebar (PassflWindow *self)
{
  GtkWidget *tbv = adw_toolbar_view_new ();
  GtkWidget *header = adw_header_bar_new ();
  GtkWidget *scrolled = gtk_scrolled_window_new ();

  self->title = ADW_WINDOW_TITLE (
      adw_window_title_new ("Pass for Linux", NULL));
  adw_header_bar_set_title_widget (ADW_HEADER_BAR (header),
                                   GTK_WIDGET (self->title));

  GMenu *menu = g_menu_new ();
  g_menu_append (menu, "_New entry", "win.new");
  g_menu_append (menu, "Re_name entry…", "win.rename");
  g_menu_append (menu, "Dupl_icate entry…", "win.copy-entry");
  g_menu_append (menu, "Re_cipients…", "win.recipients");
  g_menu_append (menu, "_Refresh", "win.refresh");
  g_menu_append (menu, "_About Pass for Linux", "win.about");
  GtkWidget *menu_btn = gtk_menu_button_new ();
  gtk_menu_button_set_icon_name (GTK_MENU_BUTTON (menu_btn),
                                 "open-menu-symbolic");
  gtk_menu_button_set_menu_model (GTK_MENU_BUTTON (menu_btn),
                                  G_MENU_MODEL (menu));
  g_object_unref (menu);
  adw_header_bar_pack_end (ADW_HEADER_BAR (header), menu_btn);

  self->btn_new = gtk_button_new_from_icon_name ("list-add-symbolic");
  gtk_widget_set_tooltip_text (self->btn_new, "New entry");
  gtk_actionable_set_action_name (GTK_ACTIONABLE (self->btn_new),
                                  "win.new");
  adw_header_bar_pack_start (ADW_HEADER_BAR (header), self->btn_new);

  self->search = gtk_search_entry_new ();
  gtk_search_entry_set_placeholder_text (GTK_SEARCH_ENTRY (self->search),
                                         "Filter entries…");
  gtk_widget_set_margin_start (self->search, 6);
  gtk_widget_set_margin_end (self->search, 6);
  gtk_widget_set_margin_bottom (self->search, 6);
  g_signal_connect_swapped (self->search, "search-changed",
                            G_CALLBACK (on_search_changed), self);

  self->list = GTK_LIST_VIEW (gtk_list_view_new (NULL, NULL));
  gtk_widget_add_css_class (GTK_WIDGET (self->list), "navigation-sidebar");
  gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scrolled),
                                 GTK_WIDGET (self->list));

  adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (tbv), header);
  adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (tbv), self->search);
  adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (tbv), scrolled);
  return tbv;
}

static GtkWidget *
build_content (PassflWindow *self)
{
  GtkWidget *tbv = adw_toolbar_view_new ();
  GtkWidget *header = adw_header_bar_new ();

  self->entry_view = PASSFL_ENTRY_VIEW (passfl_entry_view_new ());
  self->entry_edit = PASSFL_ENTRY_EDIT (passfl_entry_edit_new ());
  self->content_stack = GTK_STACK (gtk_stack_new ());
  gtk_stack_add_named (self->content_stack, GTK_WIDGET (self->entry_view),
                       "view");
  gtk_stack_add_named (self->content_stack, GTK_WIDGET (self->entry_edit),
                       "edit");

  self->btn_edit = gtk_button_new_from_icon_name ("document-edit-symbolic");
  gtk_widget_set_tooltip_text (self->btn_edit, "Edit");
  gtk_actionable_set_action_name (GTK_ACTIONABLE (self->btn_edit),
                                  "win.edit");
  gtk_widget_set_visible (self->btn_edit, FALSE);
  self->btn_delete = gtk_button_new_from_icon_name ("user-trash-symbolic");
  gtk_widget_set_tooltip_text (self->btn_delete, "Delete");
  gtk_actionable_set_action_name (GTK_ACTIONABLE (self->btn_delete),
                                  "win.delete");
  gtk_widget_set_visible (self->btn_delete, FALSE);
  self->btn_history =
      gtk_button_new_from_icon_name ("document-open-recent-symbolic");
  gtk_widget_set_tooltip_text (self->btn_history, "History");
  gtk_actionable_set_action_name (GTK_ACTIONABLE (self->btn_history),
                                  "win.history");
  gtk_widget_set_visible (self->btn_history, FALSE);
  adw_header_bar_pack_start (ADW_HEADER_BAR (header), self->btn_edit);
  adw_header_bar_pack_start (ADW_HEADER_BAR (header), self->btn_delete);
  adw_header_bar_pack_start (ADW_HEADER_BAR (header), self->btn_history);

  self->btn_cancel = gtk_button_new_with_label ("Cancel");
  gtk_actionable_set_action_name (GTK_ACTIONABLE (self->btn_cancel),
                                  "win.cancel");
  gtk_widget_set_visible (self->btn_cancel, FALSE);
  self->btn_save = gtk_button_new_with_label ("Save");
  gtk_widget_add_css_class (self->btn_save, "suggested-action");
  gtk_actionable_set_action_name (GTK_ACTIONABLE (self->btn_save),
                                  "win.save");
  gtk_widget_set_visible (self->btn_save, FALSE);
  adw_header_bar_pack_end (ADW_HEADER_BAR (header), self->btn_save);
  adw_header_bar_pack_end (ADW_HEADER_BAR (header), self->btn_cancel);

  self->reenc_banner = ADW_BANNER (adw_banner_new (
      "Not encrypted to the resolved keys — pass init would fix this"));
  adw_banner_set_button_label (self->reenc_banner, "Details");
  g_signal_connect_swapped (self->reenc_banner, "button-clicked",
                            G_CALLBACK (act_recipients_from_banner), self);

  {
    GtkWidget *vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

    gtk_box_append (GTK_BOX (vbox), GTK_WIDGET (self->reenc_banner));
    gtk_widget_set_vexpand (GTK_WIDGET (self->content_stack), TRUE);
    gtk_box_append (GTK_BOX (vbox), GTK_WIDGET (self->content_stack));
    adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (tbv), header);
    adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (tbv), vbox);
  }
  return tbv;
}

static void
passfl_window_dispose (GObject *obj)
{
  PassflWindow *self = PASSFL_WINDOW (obj);

  g_clear_handle_id (&self->search_debounce_id, g_source_remove);
  self->decrypt_epoch++; /* in-flight decrypts drop their result */
  self->toasts = NULL;   /* sentinel for decrypt_done */
  self->entry_view = NULL;
  self->entry_edit = NULL;
  self->tree_sel = NULL;
  g_clear_pointer (&self->watch, passfl_store_watch_free);
  g_clear_pointer (&self->current_rel, g_free);
  g_clear_pointer (&self->edit_orig, passfl_secbuf_free);
  g_clear_pointer (&self->pending_name, g_free);
  g_clear_pointer (&self->pending_content, passfl_secbuf_free);
  g_clear_pointer (&self->pending_message, g_free);
  g_clear_pointer (&self->pending_mvcp_new, g_free);
  g_clear_object (&self->roots);
  if (self->flat != NULL)
    g_clear_pointer (&self->flat, g_ptr_array_unref);
  g_clear_pointer (&self->store_dir, g_free);
  G_OBJECT_CLASS (passfl_window_parent_class)->dispose (obj);
}

static void
passfl_window_class_init (PassflWindowClass *klass)
{
  G_OBJECT_CLASS (klass)->dispose = passfl_window_dispose;
}

static void
passfl_window_init (PassflWindow *self)
{
  GError *error = NULL;

  gtk_window_set_title (GTK_WINDOW (self), "Pass for Linux");
  /* Sidebar tree plus a clamped entry page fit comfortably. */
  gtk_window_set_default_size (GTK_WINDOW (self), 960, 640);
  g_action_map_add_action_entries (G_ACTION_MAP (self), win_actions,
                                   G_N_ELEMENTS (win_actions), self);

  self->store_dir = passfl_store_default_dir ();
  self->flat = g_ptr_array_new_with_free_func (g_object_unref);

  GtkWidget *split = adw_navigation_split_view_new ();
  AdwNavigationPage *sidebar_page = adw_navigation_page_new (
      build_sidebar (self), "Password Store");
  self->content_page = adw_navigation_page_new (build_content (self),
                                                "Entry");
  adw_navigation_split_view_set_sidebar (
      ADW_NAVIGATION_SPLIT_VIEW (split), sidebar_page);
  adw_navigation_split_view_set_content (
      ADW_NAVIGATION_SPLIT_VIEW (split), self->content_page);

  self->toasts = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());
  adw_toast_overlay_set_child (self->toasts, split);
  adw_application_window_set_content (ADW_APPLICATION_WINDOW (self),
                                      GTK_WIDGET (self->toasts));
  passfl_entry_view_set_toast_overlay (self->entry_view, self->toasts);

  GtkEventController *keys = gtk_event_controller_key_new ();
  gtk_event_controller_set_propagation_phase (keys, GTK_PHASE_CAPTURE);
  g_signal_connect (keys, "key-pressed", G_CALLBACK (on_main_key), self);
  gtk_widget_add_controller (GTK_WIDGET (self), keys);

  /* Type-ahead: typing anywhere lands in the filter (§9). */
  gtk_search_entry_set_key_capture_widget (GTK_SEARCH_ENTRY (self->search),
                                           GTK_WIDGET (self));

  {
    g_autofree char *home_dir = g_strconcat (g_get_home_dir (), "/", NULL);
    if (g_str_has_prefix (self->store_dir, home_dir))
      {
        g_autofree char *pretty =
            g_strconcat ("~/", self->store_dir + strlen (home_dir), NULL);
        adw_window_title_set_subtitle (self->title, pretty);
      }
    else
      adw_window_title_set_subtitle (self->title, self->store_dir);
  }

  if (!passfl_crypto_init (&error))
    {
      passfl_entry_view_show_error (self->entry_view, "Crypto unavailable",
                                    error->message);
      g_clear_error (&error);
    }
  rebuild_sidebar (self);
  /* §7.7: the CLI edits the same store — pick its changes up live. */
  self->watch = passfl_store_watch_new (self->store_dir, on_store_changed,
                                        self);
  gtk_widget_grab_focus (self->search);
}

GtkWidget *
passfl_window_new (AdwApplication *app)
{
  return g_object_new (PASSFL_TYPE_WINDOW, "application", app, NULL);
}
