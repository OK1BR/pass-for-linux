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
#include "entry-view.h"
#include "entry.h"
#include "store.h"

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
  AdwWindowTitle *title;

  guint search_debounce_id;
  guint decrypt_epoch;         /* bumped per selection and per dispose */
};

G_DEFINE_FINAL_TYPE (PassflWindow, passfl_window, ADW_TYPE_APPLICATION_WINDOW)

static void rebuild_sidebar (PassflWindow *self);
static void open_entry (PassflWindow *self, const char *rel);

/* --- decrypt flow ---------------------------------------------------------- */

typedef struct {
  PassflWindow *self;          /* strong ref held for the job */
  guint epoch;
  char *rel;
  char *path;
  PassflSecBuf *buf;
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
  if (item != NULL && !item->is_dir)
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
  search_apply (self); /* re-shows tree or re-runs the active search */
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
};

static gboolean
on_main_key (GtkEventControllerKey *ctl, guint keyval, guint keycode,
             GdkModifierType state, gpointer data)
{
  PassflWindow *self = data;

  (void) ctl;
  (void) keycode;
  if (state & (GDK_CONTROL_MASK | GDK_ALT_MASK | GDK_SUPER_MASK))
    return FALSE;
  if (adw_application_window_get_visible_dialog (
          ADW_APPLICATION_WINDOW (self)))
    return FALSE;
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
  g_menu_append (menu, "_Refresh", "win.refresh");
  g_menu_append (menu, "_About Pass for Linux", "win.about");
  GtkWidget *menu_btn = gtk_menu_button_new ();
  gtk_menu_button_set_icon_name (GTK_MENU_BUTTON (menu_btn),
                                 "open-menu-symbolic");
  gtk_menu_button_set_menu_model (GTK_MENU_BUTTON (menu_btn),
                                  G_MENU_MODEL (menu));
  g_object_unref (menu);
  adw_header_bar_pack_end (ADW_HEADER_BAR (header), menu_btn);

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
  adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (tbv), header);
  adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (tbv),
                                GTK_WIDGET (self->entry_view));
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
  self->tree_sel = NULL;
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
  gtk_widget_grab_focus (self->search);
}

GtkWidget *
passfl_window_new (AdwApplication *app)
{
  return g_object_new (PASSFL_TYPE_WINDOW, "application", app, NULL);
}
