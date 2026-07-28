/* history.c — per-entry git history with plaintext diffs, M3 (SPEC §9).
 *
 * Selecting a commit decrypts the entry as of that commit and as of the
 * previous one that touched it, and shows a line diff — natively, the
 * way `git diff` with pass's gpg textconv would (§6), no subprocess.
 * Old revisions live in secure memory like the current one; the diff
 * labels expose them to the widget tree exactly as long as the dialog
 * shows them. Decryption runs on a worker thread (agent may prompt).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "history.h"

#include <string.h>

#include "entry.h"
#include "vcs.h"

struct _PassflHistory {
  AdwDialog parent_instance;

  char *store_dir;
  char *rel;
  char *path;                  /* absolute …/rel.gpg */
  PassflHistoryRestoreFunc on_restore;
  gpointer user_data;

  GPtrArray *log;              /* PassflVcsCommit */
  GtkListBox *commit_list;
  GtkWidget *diff_box;         /* rows of the current diff */
  GtkWidget *restore_btn;
  AdwStatusPage *placeholder;
  GtkStack *stack;             /* "empty" | "diff" */

  PassflEntry *sel_entry;      /* plaintext at the selected commit */
  guint job_epoch;
};

G_DEFINE_FINAL_TYPE (PassflHistory, passfl_history, ADW_TYPE_DIALOG)

/* --- line diff -------------------------------------------------------------- */

typedef struct {
  char kind;        /* ' ', '+', '-' */
  const char *text; /* borrowed from a PassflEntry */
} DiffRow;

/* Plain LCS over lines — entries are tiny, O(n·m) is fine. */
static GArray *
diff_lines (PassflEntry *old, PassflEntry *new)
{
  guint n = old != NULL ? passfl_entry_n_lines (old) : 0;
  guint m = new != NULL ? passfl_entry_n_lines (new) : 0;
  g_autofree guint *lcs = g_new0 (guint, (n + 1) * (m + 1));
  GArray *rows = g_array_new (FALSE, FALSE, sizeof (DiffRow));
  guint i, j;

#define L(i, j) lcs[(i) * (m + 1) + (j)]
  for (i = n; i > 0; i--)
    for (j = m; j > 0; j--)
      {
        if (strcmp (passfl_entry_line (old, i - 1),
                    passfl_entry_line (new, j - 1)) == 0)
          L (i - 1, j - 1) = L (i, j) + 1;
        else
          L (i - 1, j - 1) = MAX (L (i, j - 1), L (i - 1, j));
      }

  i = 0;
  j = 0;
  while (i < n && j < m)
    {
      DiffRow row;

      if (strcmp (passfl_entry_line (old, i),
                  passfl_entry_line (new, j)) == 0)
        {
          row = (DiffRow) { ' ', passfl_entry_line (old, i) };
          i++;
          j++;
        }
      else if (L (i + 1, j) >= L (i, j + 1))
        {
          row = (DiffRow) { '-', passfl_entry_line (old, i) };
          i++;
        }
      else
        {
          row = (DiffRow) { '+', passfl_entry_line (new, j) };
          j++;
        }
      g_array_append_val (rows, row);
    }
  for (; i < n; i++)
    {
      DiffRow row = { '-', passfl_entry_line (old, i) };

      g_array_append_val (rows, row);
    }
  for (; j < m; j++)
    {
      DiffRow row = { '+', passfl_entry_line (new, j) };

      g_array_append_val (rows, row);
    }
#undef L
  return rows;
}

static void
render_diff (PassflHistory *self, PassflEntry *old, PassflEntry *new)
{
  g_autoptr (GArray) rows = diff_lines (old, new);
  GtkWidget *child;

  while ((child = gtk_widget_get_first_child (self->diff_box)) != NULL)
    gtk_box_remove (GTK_BOX (self->diff_box), child);

  for (guint k = 0; k < rows->len; k++)
    {
      const DiffRow *row = &g_array_index (rows, DiffRow, k);
      g_autofree char *text =
          g_strdup_printf ("%c %s", row->kind, row->text);
      GtkWidget *label = gtk_label_new (text);

      gtk_label_set_xalign (GTK_LABEL (label), 0);
      gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
      gtk_widget_add_css_class (label, "monospace");
      if (row->kind == '+')
        gtk_widget_add_css_class (label, "success");
      else if (row->kind == '-')
        gtk_widget_add_css_class (label, "error");
      else
        gtk_widget_add_css_class (label, "dim-label");
      gtk_box_append (GTK_BOX (self->diff_box), label);
    }
  gtk_stack_set_visible_child_name (self->stack, "diff");
  gtk_widget_set_sensitive (self->restore_btn, TRUE);
}

/* --- revision loading -------------------------------------------------------- */

typedef struct {
  PassflHistory *self; /* strong ref */
  guint epoch;
  char *oid_new;
  char *oid_old;       /* NULL for the first commit of the entry */
  PassflEntry *entry_new;
  PassflEntry *entry_old;
  GError *error;
} RevisionJob;

static PassflEntry *
load_revision (PassflHistory *self, const char *oid, GError **error)
{
  PassflVcs *vcs = passfl_vcs_open (self->store_dir, self->path, error);
  GBytes *blob;
  PassflSecBuf *plain;
  PassflEntry *entry = NULL;

  if (vcs == NULL)
    return NULL;
  blob = passfl_vcs_file_at (vcs, oid, self->path, error);
  if (blob != NULL)
    {
      plain = passfl_crypto_decrypt_mem (g_bytes_get_data (blob, NULL),
                                         g_bytes_get_size (blob), error);
      if (plain != NULL)
        {
          entry = passfl_entry_parse (plain->data, plain->len);
          passfl_secbuf_free (plain);
        }
      g_bytes_unref (blob);
    }
  passfl_vcs_free (vcs);
  return entry;
}

static gboolean
revision_done (gpointer data)
{
  RevisionJob *job = data;
  PassflHistory *self = job->self;

  if (self->commit_list == NULL || job->epoch != self->job_epoch)
    goto out; /* dialog gone or selection moved on */

  if (job->entry_new == NULL)
    {
      adw_status_page_set_title (self->placeholder,
                                 job->error != NULL ? job->error->message
                                                    : "Cannot load revision");
      gtk_stack_set_visible_child_name (self->stack, "empty");
      goto out;
    }

  g_clear_pointer (&self->sel_entry, passfl_entry_free);
  self->sel_entry = g_steal_pointer (&job->entry_new);
  render_diff (self, job->entry_old, self->sel_entry);

out:
  g_clear_pointer (&job->entry_new, passfl_entry_free);
  g_clear_pointer (&job->entry_old, passfl_entry_free);
  g_clear_error (&job->error);
  g_free (job->oid_new);
  g_free (job->oid_old);
  g_object_unref (job->self);
  g_free (job);
  return G_SOURCE_REMOVE;
}

static gpointer
revision_thread (gpointer data)
{
  RevisionJob *job = data;

  job->entry_new = load_revision (job->self, job->oid_new, &job->error);
  if (job->entry_new != NULL && job->oid_old != NULL)
    job->entry_old = load_revision (job->self, job->oid_old, NULL);
  g_idle_add (revision_done, job);
  return NULL;
}

static void
on_commit_selected (PassflHistory *self, GtkListBoxRow *row)
{
  guint idx;
  const PassflVcsCommit *commit;
  RevisionJob *job;

  if (row == NULL)
    return;
  idx = (guint) gtk_list_box_row_get_index (row);
  if (idx >= self->log->len)
    return;
  commit = g_ptr_array_index (self->log, idx);

  self->job_epoch++;
  gtk_widget_set_sensitive (self->restore_btn, FALSE);
  job = g_new0 (RevisionJob, 1);
  job->self = g_object_ref (self);
  job->epoch = self->job_epoch;
  job->oid_new = g_strdup (commit->oid);
  if (idx + 1 < self->log->len)
    {
      const PassflVcsCommit *prev =
          g_ptr_array_index (self->log, idx + 1);

      job->oid_old = g_strdup (prev->oid);
    }
  g_thread_unref (g_thread_new ("passfl-revision", revision_thread, job));
}

/* --- restore ---------------------------------------------------------------- */

static void
on_restore_clicked (PassflHistory *self)
{
  PassflSecBuf *content;
  guint n;
  gsize total = 0;
  char *p;

  if (self->sel_entry == NULL || self->on_restore == NULL)
    return;

  /* reassemble the revision's exact bytes from its parsed lines */
  n = passfl_entry_n_lines (self->sel_entry);
  for (guint i = 0; i < n; i++)
    total += strlen (passfl_entry_line (self->sel_entry, i)) + 1;
  if (!passfl_entry_final_newline (self->sel_entry) && total > 0)
    total--;
  content = passfl_secbuf_new_sized (total);
  p = content->data;
  for (guint i = 0; i < n; i++)
    {
      const char *line = passfl_entry_line (self->sel_entry, i);
      gsize len = strlen (line);

      memcpy (p, line, len);
      p += len;
      if (i + 1 < n || passfl_entry_final_newline (self->sel_entry))
        *p++ = '\n';
    }

  self->on_restore (self->rel, content, self->user_data);
  adw_dialog_close (ADW_DIALOG (self));
}

/* --- construction ------------------------------------------------------------ */

static void
passfl_history_dispose (GObject *obj)
{
  PassflHistory *self = PASSFL_HISTORY (obj);

  self->job_epoch++;
  self->commit_list = NULL; /* sentinel for revision_done */
  g_clear_pointer (&self->sel_entry, passfl_entry_free);
  g_clear_pointer (&self->log, g_ptr_array_unref);
  g_clear_pointer (&self->store_dir, g_free);
  g_clear_pointer (&self->rel, g_free);
  g_clear_pointer (&self->path, g_free);
  G_OBJECT_CLASS (passfl_history_parent_class)->dispose (obj);
}

static void
passfl_history_class_init (PassflHistoryClass *klass)
{
  G_OBJECT_CLASS (klass)->dispose = passfl_history_dispose;
}

static void
passfl_history_init (PassflHistory *self)
{
  (void) self; /* built in passfl_history_new, once the paths are known */
}

static void
build_ui (PassflHistory *self)
{
  GtkWidget *tbv = adw_toolbar_view_new ();
  GtkWidget *header = adw_header_bar_new ();
  GtkWidget *paned = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
  GtkWidget *list_scroll = gtk_scrolled_window_new ();
  GtkWidget *diff_scroll = gtk_scrolled_window_new ();
  g_autofree char *title = g_strdup_printf ("History — %s", self->rel);

  adw_dialog_set_title (ADW_DIALOG (self), title);
  adw_dialog_set_content_width (ADW_DIALOG (self), 720);
  adw_dialog_set_content_height (ADW_DIALOG (self), 480);

  self->commit_list = GTK_LIST_BOX (gtk_list_box_new ());
  gtk_list_box_set_selection_mode (self->commit_list, GTK_SELECTION_SINGLE);
  gtk_widget_add_css_class (GTK_WIDGET (self->commit_list),
                            "navigation-sidebar");
  g_signal_connect_swapped (self->commit_list, "row-selected",
                            G_CALLBACK (on_commit_selected), self);

  for (guint i = 0; i < self->log->len; i++)
    {
      const PassflVcsCommit *commit = g_ptr_array_index (self->log, i);
      GtkWidget *row = adw_action_row_new ();
      g_autoptr (GDateTime) when =
          g_date_time_new_from_unix_local (commit->time);
      g_autofree char *date =
          g_date_time_format (when, "%Y-%m-%d %H:%M");

      adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row),
                                          FALSE);
      adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row),
                                     commit->summary);
      adw_action_row_set_subtitle (ADW_ACTION_ROW (row), date);
      gtk_list_box_append (self->commit_list, row);
    }

  gtk_widget_set_size_request (list_scroll, 300, -1);
  gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (list_scroll),
                                 GTK_WIDGET (self->commit_list));

  self->stack = GTK_STACK (gtk_stack_new ());
  self->placeholder = ADW_STATUS_PAGE (adw_status_page_new ());
  adw_status_page_set_icon_name (self->placeholder,
                                 "document-open-recent-symbolic");
  adw_status_page_set_title (self->placeholder, "Select a revision");
  gtk_stack_add_named (self->stack, GTK_WIDGET (self->placeholder),
                       "empty");
  self->diff_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
  gtk_widget_set_margin_top (self->diff_box, 12);
  gtk_widget_set_margin_bottom (self->diff_box, 12);
  gtk_widget_set_margin_start (self->diff_box, 12);
  gtk_widget_set_margin_end (self->diff_box, 12);
  gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (diff_scroll),
                                 self->diff_box);
  gtk_stack_add_named (self->stack, diff_scroll, "diff");
  gtk_widget_set_hexpand (GTK_WIDGET (self->stack), TRUE);

  self->restore_btn = gtk_button_new_with_label ("Restore this version");
  gtk_widget_add_css_class (self->restore_btn, "suggested-action");
  gtk_widget_set_sensitive (self->restore_btn, FALSE);
  g_signal_connect_swapped (self->restore_btn, "clicked",
                            G_CALLBACK (on_restore_clicked), self);
  adw_header_bar_pack_end (ADW_HEADER_BAR (header), self->restore_btn);

  gtk_box_append (GTK_BOX (paned), list_scroll);
  gtk_box_append (GTK_BOX (paned),
                  gtk_separator_new (GTK_ORIENTATION_VERTICAL));
  gtk_box_append (GTK_BOX (paned), GTK_WIDGET (self->stack));

  adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (tbv), header);
  adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (tbv), paned);
  adw_dialog_set_child (ADW_DIALOG (self), tbv);
}

AdwDialog *
passfl_history_new (const char *store_dir, const char *rel,
                    PassflHistoryRestoreFunc on_restore, gpointer user_data)
{
  PassflHistory *self;
  GError *error = NULL;
  g_autofree char *path = NULL;
  PassflVcs *vcs;
  GPtrArray *log = NULL;

  g_return_val_if_fail (store_dir != NULL, NULL);
  g_return_val_if_fail (rel != NULL, NULL);

  gboolean had_repo;

  path = g_strconcat (store_dir, "/", rel, ".gpg", NULL);
  vcs = passfl_vcs_open (store_dir, path, &error);
  had_repo = vcs != NULL;
  if (vcs != NULL)
    {
      log = passfl_vcs_history (vcs, path, &error);
      passfl_vcs_free (vcs);
    }

  self = g_object_new (PASSFL_TYPE_HISTORY, NULL);
  self->store_dir = g_strdup (store_dir);
  self->rel = g_strdup (rel);
  self->path = g_steal_pointer (&path);
  self->on_restore = on_restore;
  self->user_data = user_data;
  self->log = log != NULL ? log : g_ptr_array_new ();
  g_clear_error (&error);

  build_ui (self);
  if (self->log->len == 0)
    {
      adw_status_page_set_title (self->placeholder,
                                 had_repo
                                     ? "No history for this entry"
                                     : "This store is not a git repository");
      gtk_widget_set_sensitive (self->restore_btn, FALSE);
    }
  return ADW_DIALOG (self);
}
