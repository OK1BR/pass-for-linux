/* recipient-view.c — recipients of a subtree + re-encryption, M4 (§9).
 *
 * Shows what §2.2 resolution decides for the entry's directory — which
 * .gpg-id won and which keys the strings resolve to — plus the §4.10
 * warning when the entry's actual PKESK key IDs disagree with that
 * (the state `pass init` would fix). "Re-encrypt subtree" runs the
 * engine's §4.10 diff over the winning .gpg-id's subtree on a worker
 * thread and commits with the same message a re-run of `pass init`
 * would have produced.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "recipient-view.h"

#include <string.h>

#include "crypto.h"
#include "recipients.h"
#include "store.h"
#include "vcs.h"

struct _PassflRecipientView {
  AdwDialog parent_instance;

  char *store_dir;
  char *rel;
  char *gpg_id_file;      /* the winning .gpg-id, NULL for env override */
  GStrv ids;              /* parsed recipient strings */
  PassflRecipientReencFunc on_reenc;
  gpointer user_data;

  GtkWidget *reenc_btn;
  AdwToastOverlay *toasts;
  gboolean running;
};

G_DEFINE_FINAL_TYPE (PassflRecipientView, passfl_recipient_view,
                     ADW_TYPE_DIALOG)

/* --- re-encrypt worker ------------------------------------------------------ */

typedef struct {
  PassflRecipientView *self; /* strong ref */
  char *target;              /* subtree of the winning .gpg-id */
  char *subpath;             /* its path relative to the root, "" = root */
  guint n_changed;
  gboolean ok;
  GError *error;
} ReencJob;

static gboolean
reenc_done (gpointer data)
{
  ReencJob *job = data;
  PassflRecipientView *self = job->self;

  if (self->reenc_btn != NULL)
    {
      self->running = FALSE;
      gtk_widget_set_sensitive (self->reenc_btn, TRUE);
      if (!job->ok)
        adw_toast_overlay_add_toast (
            self->toasts,
            adw_toast_new (job->error != NULL ? job->error->message
                                              : "Re-encryption failed"));
      else if (self->on_reenc != NULL)
        {
          self->on_reenc (job->n_changed, self->user_data);
          adw_dialog_close (ADW_DIALOG (self));
        }
    }

  g_clear_error (&job->error);
  g_free (job->target);
  g_free (job->subpath);
  g_object_unref (job->self);
  g_free (job);
  return G_SOURCE_REMOVE;
}

static gpointer
reenc_thread (gpointer data)
{
  ReencJob *job = data;
  PassflRecipientView *self = job->self;

  job->ok = passfl_store_reencrypt (self->store_dir, job->target, NULL,
                                    NULL, &job->n_changed, &job->error);
  if (job->ok && job->n_changed > 0)
    {
      /* commit like a re-run of `pass init` with the same ids would */
      g_autofree char *ids_joined =
          g_strjoinv (", ", self->ids != NULL ? self->ids : (char *[]){ NULL });
      g_autofree char *message =
          passfl_vcs_msg_reencrypt (ids_joined, job->subpath);
      PassflVcs *vcs =
          passfl_vcs_open (self->store_dir, job->target, NULL);

      if (vcs != NULL)
        {
          const char *paths[] = { job->target, NULL };

          job->ok = passfl_vcs_commit_paths (vcs, paths, message,
                                             &job->error);
          passfl_vcs_free (vcs);
        }
    }
  g_idle_add (reenc_done, job);
  return NULL;
}

static void
on_reencrypt_clicked (PassflRecipientView *self)
{
  ReencJob *job;

  if (self->running)
    return;
  self->running = TRUE;
  gtk_widget_set_sensitive (self->reenc_btn, FALSE);

  job = g_new0 (ReencJob, 1);
  job->self = g_object_ref (self);
  if (self->gpg_id_file != NULL)
    {
      job->target = g_path_get_dirname (self->gpg_id_file);
      job->subpath = strcmp (job->target, self->store_dir) == 0
          ? g_strdup ("")
          : g_strdup (job->target + strlen (self->store_dir) + 1);
    }
  else
    {
      job->target = g_strdup (self->store_dir); /* PASSWORD_STORE_KEY */
      job->subpath = g_strdup ("");
    }
  g_thread_unref (g_thread_new ("passfl-reencrypt", reenc_thread, job));
}

/* --- construction ------------------------------------------------------------ */

static void
passfl_recipient_view_dispose (GObject *obj)
{
  PassflRecipientView *self = PASSFL_RECIPIENT_VIEW (obj);

  self->reenc_btn = NULL; /* sentinel for reenc_done */
  g_clear_pointer (&self->store_dir, g_free);
  g_clear_pointer (&self->rel, g_free);
  g_clear_pointer (&self->gpg_id_file, g_free);
  g_clear_pointer (&self->ids, g_strfreev);
  G_OBJECT_CLASS (passfl_recipient_view_parent_class)->dispose (obj);
}

static void
passfl_recipient_view_class_init (PassflRecipientViewClass *klass)
{
  G_OBJECT_CLASS (klass)->dispose = passfl_recipient_view_dispose;
}

static void
passfl_recipient_view_init (PassflRecipientView *self)
{
  (void) self;
}

AdwDialog *
passfl_recipient_view_new (const char *store_dir, const char *rel,
                           PassflRecipientReencFunc on_reenc,
                           gpointer user_data)
{
  PassflRecipientView *self;
  GError *error = NULL;
  g_autofree char *dir_rel = NULL;
  char *slash;
  gboolean needed = FALSE;

  g_return_val_if_fail (store_dir != NULL, NULL);
  g_return_val_if_fail (rel != NULL, NULL);

  self = g_object_new (PASSFL_TYPE_RECIPIENT_VIEW, NULL);
  self->store_dir = g_strdup (store_dir);
  self->rel = g_strdup (rel);
  self->on_reenc = on_reenc;
  self->user_data = user_data;

  dir_rel = g_strdup (rel);
  slash = strrchr (dir_rel, '/');
  if (slash != NULL)
    *slash = '\0';
  else
    dir_rel[0] = '\0';

  self->ids = passfl_recipients_resolve (store_dir, dir_rel,
                                         &self->gpg_id_file, &error);
  passfl_store_entry_needs_reencrypt (store_dir, rel, &needed, NULL);

  {
    GtkWidget *tbv = adw_toolbar_view_new ();
    GtkWidget *header = adw_header_bar_new ();
    GtkWidget *scrolled = gtk_scrolled_window_new ();
    GtkWidget *clamp = adw_clamp_new ();
    GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *group = adw_preferences_group_new ();
    g_autofree char *title = g_strdup_printf (
        "Recipients — %s", *dir_rel != '\0' ? dir_rel : "store root");

    adw_dialog_set_title (ADW_DIALOG (self), title);
    adw_dialog_set_content_width (ADW_DIALOG (self), 560);
    adw_dialog_set_content_height (ADW_DIALOG (self), 420);

    if (needed)
      {
        AdwBanner *banner = ADW_BANNER (adw_banner_new (
            "This entry is not encrypted to the resolved keys — "
            "the state `pass init` would fix"));

        adw_banner_set_revealed (banner, TRUE);
        gtk_box_append (GTK_BOX (body), GTK_WIDGET (banner));
      }

    adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (group),
                                     "Encrypted to");
    adw_preferences_group_set_description (
        ADW_PREFERENCES_GROUP (group),
        self->gpg_id_file != NULL ? self->gpg_id_file
                                  : "$PASSWORD_STORE_KEY (no file "
                                    "consulted)");

    if (self->ids == NULL)
      {
        GtkWidget *row = adw_action_row_new ();

        adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row),
                                            FALSE);
        adw_preferences_row_set_title (
            ADW_PREFERENCES_ROW (row),
            error != NULL ? error->message : "Cannot resolve recipients");
        adw_preferences_group_add (ADW_PREFERENCES_GROUP (group), row);
      }
    else
      for (guint i = 0; self->ids[i] != NULL; i++)
        {
          GtkWidget *row = adw_action_row_new ();
          g_autofree char *desc =
              passfl_crypto_describe_recipient (self->ids[i]);

          adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row),
                                              FALSE);
          adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row),
                                         self->ids[i]);
          adw_action_row_set_subtitle (ADW_ACTION_ROW (row),
                                       desc != NULL
                                           ? desc
                                           : "no usable key found");
          if (desc == NULL)
            gtk_widget_add_css_class (row, "error");
          adw_preferences_group_add (ADW_PREFERENCES_GROUP (group), row);
        }
    gtk_box_append (GTK_BOX (body), group);

    self->reenc_btn =
        gtk_button_new_with_label ("Re-encrypt subtree");
    gtk_widget_set_tooltip_text (self->reenc_btn,
                                 "Run the §4.10 diff: rewrite only "
                                 "entries whose keys disagree");
    if (needed)
      gtk_widget_add_css_class (self->reenc_btn, "suggested-action");
    g_signal_connect_swapped (self->reenc_btn, "clicked",
                              G_CALLBACK (on_reencrypt_clicked), self);
    adw_header_bar_pack_end (ADW_HEADER_BAR (header), self->reenc_btn);

    gtk_widget_set_margin_top (body, 12);
    gtk_widget_set_margin_bottom (body, 12);
    gtk_widget_set_margin_start (body, 12);
    gtk_widget_set_margin_end (body, 12);
    adw_clamp_set_child (ADW_CLAMP (clamp), body);
    gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scrolled), clamp);

    self->toasts = ADW_TOAST_OVERLAY (adw_toast_overlay_new ());
    adw_toast_overlay_set_child (self->toasts, scrolled);
    adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (tbv), header);
    adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (tbv),
                                  GTK_WIDGET (self->toasts));
    adw_dialog_set_child (ADW_DIALOG (self), tbv);
  }
  g_clear_error (&error);
  return ADW_DIALOG (self);
}
