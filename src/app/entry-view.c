/* entry-view.c — one decrypted entry, M1 (docs/SPEC.md §7.4, §9).
 *
 * The PassflEntry stays in secure memory; what GTK renders (a revealed
 * password, a copied value) necessarily passes through ordinary widget
 * and clipboard memory — that exposure is kept as short as the user
 * asks for: masked by default, unmasked only while toggled, clipboard
 * cleared after $PASSWORD_STORE_CLIP_TIME with the previous content
 * restored (§7.4). Losing clipboard ownership to another app cancels
 * the restore instead of clobbering what the user copied since.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "entry-view.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

#define MASK "••••••••••" /* fixed width — never leaks the real length */
#define DEFAULT_CLIP_TIME 45

struct _PassflEntryView {
  GtkBox parent_instance;

  AdwToastOverlay *toasts;   /* borrowed from the window */
  GtkStack *stack;           /* "status" | "entry" */
  AdwStatusPage *status;
  GtkWidget *groups_box;     /* rebuilt per entry */
  PassflEntry *entry;        /* owned; wiped on replace/dispose */

  /* Clipboard countdown state — independent of the shown entry. */
  PassflSecBuf *clip_pending;   /* secret waiting for the previous-content read */
  GCancellable *clip_cancel;    /* cancels that read */
  guint clip_fallback_id;       /* gives up on the read, copies anyway */
  char *clip_restore;           /* what to put back when the timer ends */
  AdwToast *clip_toast;         /* owned ref; title ticks down */
  guint clip_timer_id;
  int clip_remaining;
  gulong clip_changed_id;       /* "changed" on GdkClipboard while armed */
  gboolean clip_setting;        /* guard: the change is our own */
};

G_DEFINE_FINAL_TYPE (PassflEntryView, passfl_entry_view, GTK_TYPE_BOX)

/* --- clipboard with clear timer ----------------------------------------- */

static GdkClipboard *
clipboard (PassflEntryView *self)
{
  return gdk_display_get_clipboard (
      gtk_widget_get_display (GTK_WIDGET (self)));
}

static int
clip_time (void)
{
  const char *env = g_getenv ("PASSWORD_STORE_CLIP_TIME");
  int t = env != NULL ? atoi (env) : 0;

  return t > 0 ? t : DEFAULT_CLIP_TIME;
}

static void
clip_set_text (PassflEntryView *self, const char *text)
{
  self->clip_setting = TRUE;
  gdk_clipboard_set_text (clipboard (self), text);
  self->clip_setting = FALSE;
}

/* Tear the countdown down. When restore is TRUE and we still own the
 * clipboard, put the previous content back (or clear it). */
static void
clip_disarm (PassflEntryView *self, gboolean restore)
{
  g_clear_handle_id (&self->clip_timer_id, g_source_remove);
  g_clear_handle_id (&self->clip_fallback_id, g_source_remove);
  g_cancellable_cancel (self->clip_cancel);
  g_clear_object (&self->clip_cancel);
  if (self->clip_changed_id != 0)
    {
      g_signal_handler_disconnect (clipboard (self), self->clip_changed_id);
      self->clip_changed_id = 0;
    }
  if (restore && gdk_clipboard_is_local (clipboard (self)))
    clip_set_text (self, self->clip_restore != NULL ? self->clip_restore : "");
  g_clear_pointer (&self->clip_restore, g_free);
  g_clear_pointer (&self->clip_pending, passfl_secbuf_free);
  if (self->clip_toast != NULL)
    {
      adw_toast_dismiss (self->clip_toast);
      g_clear_object (&self->clip_toast);
    }
}

static gboolean
clip_tick (gpointer data)
{
  PassflEntryView *self = data;

  self->clip_remaining--;
  if (self->clip_remaining <= 0)
    {
      self->clip_timer_id = 0; /* removed by returning FALSE below */
      clip_disarm (self, TRUE);
      return G_SOURCE_REMOVE;
    }
  if (self->clip_toast != NULL)
    {
      g_autofree char *title =
          g_strdup_printf ("Copied — clears in %d s", self->clip_remaining);
      adw_toast_set_title (self->clip_toast, title);
    }
  return G_SOURCE_CONTINUE;
}

static void
on_clip_changed (GdkClipboard *cb, gpointer data)
{
  PassflEntryView *self = data;

  (void) cb;
  if (self->clip_setting)
    return;
  /* Someone else owns the clipboard now — never clobber it (§7.4). */
  clip_disarm (self, FALSE);
}

static void
on_prev_clip_read (GObject *source, GAsyncResult *res, gpointer data)
{
  PassflEntryView *self = data;
  char *prev = gdk_clipboard_read_text_finish (GDK_CLIPBOARD (source), res,
                                               NULL);

  if (self->clip_pending == NULL) /* disarmed while the read was in flight */
    {
      g_free (prev);
      g_object_unref (self);
      return;
    }
  g_clear_handle_id (&self->clip_fallback_id, g_source_remove);
  g_clear_object (&self->clip_cancel);

  self->clip_restore = prev; /* may be NULL — restores to empty */
  clip_set_text (self, self->clip_pending->data);
  g_clear_pointer (&self->clip_pending, passfl_secbuf_free);

  self->clip_remaining = clip_time ();
  {
    g_autofree char *title =
        g_strdup_printf ("Copied — clears in %d s", self->clip_remaining);
    self->clip_toast = adw_toast_new (title);
  }
  adw_toast_set_timeout (self->clip_toast, 0); /* stays for the countdown */
  g_object_ref (self->clip_toast);
  self->clip_timer_id = g_timeout_add_seconds (1, clip_tick, self);
  self->clip_changed_id = g_signal_connect (clipboard (self), "changed",
                                            G_CALLBACK (on_clip_changed),
                                            self);
  if (self->toasts != NULL)
    adw_toast_overlay_add_toast (self->toasts, self->clip_toast);

  g_object_unref (self);
}

/* A clipboard owner that never delivers must not stall the copy: cancel
 * the read and proceed without anything to restore. */
static gboolean
clip_read_fallback (gpointer data)
{
  PassflEntryView *self = data;

  self->clip_fallback_id = 0;
  g_cancellable_cancel (self->clip_cancel); /* finishes on_prev_clip_read */
  return G_SOURCE_REMOVE;
}

/* Copy a secret: remember the previous clipboard content, then replace it
 * and start the visible countdown. */
static void
copy_timed (PassflEntryView *self, const char *secret)
{
  clip_disarm (self, FALSE);
  self->clip_pending = passfl_secbuf_new (secret, -1);
  self->clip_cancel = g_cancellable_new ();
  self->clip_fallback_id = g_timeout_add (400, clip_read_fallback, self);
  gdk_clipboard_read_text_async (clipboard (self), self->clip_cancel,
                                 on_prev_clip_read, g_object_ref (self));
}

static void
toast (PassflEntryView *self, const char *fmt, ...)
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

/* --- row construction ---------------------------------------------------- */

/* The secret lives on the row only through these data keys; line index
 * into self->entry, resolved on demand. */
static const char *
row_secret (PassflEntryView *self, GtkWidget *row)
{
  guint idx = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (row),
                                                   "passfl-line"));

  if (self->entry == NULL || idx >= passfl_entry_n_lines (self->entry))
    return NULL;
  return passfl_entry_line (self->entry, idx);
}

static void
on_copy_secret (GtkButton *button, gpointer data)
{
  PassflEntryView *self = data;
  GtkWidget *row = gtk_widget_get_ancestor (GTK_WIDGET (button),
                                            ADW_TYPE_ACTION_ROW);
  const char *secret = row != NULL ? row_secret (self, row) : NULL;

  if (secret != NULL)
    copy_timed (self, secret);
}

static void
on_reveal_toggled (GtkToggleButton *button, gpointer data)
{
  PassflEntryView *self = data;
  GtkWidget *row = gtk_widget_get_ancestor (GTK_WIDGET (button),
                                            ADW_TYPE_ACTION_ROW);
  const char *secret = row != NULL ? row_secret (self, row) : NULL;
  gboolean active = gtk_toggle_button_get_active (button);

  if (row == NULL || secret == NULL)
    return;
  /* Revealing copies the secret into ordinary widget memory for as long
   * as the toggle is held down — concealing puts the mask back. */
  adw_action_row_set_subtitle (ADW_ACTION_ROW (row),
                               active ? secret : MASK);
  gtk_button_set_icon_name (GTK_BUTTON (button),
                            active ? "view-conceal-symbolic"
                                   : "view-reveal-symbolic");
}

static GtkWidget *
flat_button (const char *icon, const char *tooltip)
{
  GtkWidget *btn = gtk_button_new_from_icon_name (icon);

  gtk_widget_add_css_class (btn, "flat");
  gtk_widget_set_valign (btn, GTK_ALIGN_CENTER);
  gtk_widget_set_tooltip_text (btn, tooltip);
  return btn;
}

static GtkWidget *
secret_row (PassflEntryView *self, const char *title, guint line_idx)
{
  GtkWidget *row = adw_action_row_new ();
  GtkWidget *reveal = gtk_toggle_button_new ();
  GtkWidget *copy = flat_button ("edit-copy-symbolic",
                                 "Copy (cleared after the timer)");

  adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row), FALSE);
  adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), title);
  adw_action_row_set_subtitle (ADW_ACTION_ROW (row), MASK);
  g_object_set_data (G_OBJECT (row), "passfl-line",
                     GUINT_TO_POINTER (line_idx));

  gtk_button_set_icon_name (GTK_BUTTON (reveal), "view-reveal-symbolic");
  gtk_widget_add_css_class (reveal, "flat");
  gtk_widget_set_valign (reveal, GTK_ALIGN_CENTER);
  gtk_widget_set_tooltip_text (reveal, "Reveal");
  g_signal_connect (reveal, "toggled", G_CALLBACK (on_reveal_toggled), self);
  g_signal_connect (copy, "clicked", G_CALLBACK (on_copy_secret), self);

  adw_action_row_add_suffix (ADW_ACTION_ROW (row), reveal);
  adw_action_row_add_suffix (ADW_ACTION_ROW (row), copy);
  return row;
}

static void
on_copy_value (GtkButton *button, gpointer data)
{
  PassflEntryView *self = data;
  const char *value = g_object_get_data (G_OBJECT (button), "passfl-value");

  if (value == NULL)
    return;
  /* Metadata values are not the password — plain copy, no timer, like
   * selecting them in the CLI's output. */
  clip_set_text (self, value);
  toast (self, "Copied");
}

static GtkWidget *
value_row (PassflEntryView *self, const char *title, const char *value)
{
  GtkWidget *row = adw_action_row_new ();
  GtkWidget *copy = flat_button ("edit-copy-symbolic", "Copy");

  adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row), FALSE);
  if (title != NULL)
    adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), title);
  adw_action_row_set_subtitle (ADW_ACTION_ROW (row), value);

  /* value points into the entry's secure memory and outlives the row —
   * the row is destroyed whenever the entry is replaced. */
  g_object_set_data (G_OBJECT (copy), "passfl-value", (gpointer) value);
  g_signal_connect (copy, "clicked", G_CALLBACK (on_copy_value), self);
  adw_action_row_add_suffix (ADW_ACTION_ROW (row), copy);
  return row;
}

/* Drop every row before the entry they point into goes away. */
static void
clear_groups (PassflEntryView *self)
{
  GtkWidget *child;

  while ((child = gtk_widget_get_first_child (self->groups_box)) != NULL)
    gtk_box_remove (GTK_BOX (self->groups_box), child);
}

static void
rebuild_groups (PassflEntryView *self, const char *name)
{
  GtkWidget *password_group = adw_preferences_group_new ();
  GtkWidget *details_group = NULL;
  guint n = passfl_entry_n_lines (self->entry);

  clear_groups (self);

  adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (password_group),
                                   name);
  adw_preferences_group_add (ADW_PREFERENCES_GROUP (password_group),
                             secret_row (self, "Password", 0));
  gtk_box_append (GTK_BOX (self->groups_box), password_group);

  for (guint i = 1; i < n; i++)
    {
      const char *line = passfl_entry_line (self->entry, i);
      const char *value;
      gsize key_len;
      GtkWidget *row;

      if (*line == '\0')
        continue;

      if (passfl_entry_line_is_otp (line))
        row = secret_row (self, "OTP secret", i);
      else if (passfl_entry_line_kv (line, &key_len, &value))
        {
          g_autofree char *key = g_strndup (line, key_len);
          row = value_row (self, key, value);
        }
      else
        row = value_row (self, NULL, line);

      if (details_group == NULL)
        {
          details_group = adw_preferences_group_new ();
          adw_preferences_group_set_title (
              ADW_PREFERENCES_GROUP (details_group), "Details");
          gtk_box_append (GTK_BOX (self->groups_box), details_group);
        }
      adw_preferences_group_add (ADW_PREFERENCES_GROUP (details_group), row);
    }
}

/* --- public state switches ----------------------------------------------- */

void
passfl_entry_view_show_placeholder (PassflEntryView *self)
{
  g_return_if_fail (PASSFL_IS_ENTRY_VIEW (self));

  clear_groups (self);
  g_clear_pointer (&self->entry, passfl_entry_free);
  adw_status_page_set_icon_name (self->status,
                                 "dialog-password-symbolic");
  adw_status_page_set_title (self->status, "Password Store");
  adw_status_page_set_description (self->status,
                                   "Select an entry to view it");
  gtk_stack_set_visible_child_name (self->stack, "status");
}

void
passfl_entry_view_show_error (PassflEntryView *self, const char *name,
                              const char *message)
{
  g_return_if_fail (PASSFL_IS_ENTRY_VIEW (self));

  clear_groups (self);
  g_clear_pointer (&self->entry, passfl_entry_free);
  adw_status_page_set_icon_name (self->status, "dialog-error-symbolic");
  adw_status_page_set_title (self->status, name);
  adw_status_page_set_description (self->status, message);
  gtk_stack_set_visible_child_name (self->stack, "status");
}

void
passfl_entry_view_show_entry (PassflEntryView *self, const char *name,
                              PassflEntry *entry)
{
  g_return_if_fail (PASSFL_IS_ENTRY_VIEW (self));
  g_return_if_fail (entry != NULL);

  g_clear_pointer (&self->entry, passfl_entry_free);
  self->entry = entry;
  rebuild_groups (self, name);
  gtk_stack_set_visible_child_name (self->stack, "entry");
}

PassflEntry *
passfl_entry_view_steal_entry (PassflEntryView *self)
{
  PassflEntry *entry;

  g_return_val_if_fail (PASSFL_IS_ENTRY_VIEW (self), NULL);

  entry = g_steal_pointer (&self->entry);
  passfl_entry_view_show_placeholder (self);
  return entry;
}

void
passfl_entry_view_set_toast_overlay (PassflEntryView *self,
                                     AdwToastOverlay *toasts)
{
  g_return_if_fail (PASSFL_IS_ENTRY_VIEW (self));
  self->toasts = toasts;
}

/* --- boilerplate ---------------------------------------------------------- */

static void
passfl_entry_view_dispose (GObject *obj)
{
  PassflEntryView *self = PASSFL_ENTRY_VIEW (obj);

  /* Window going away: finish the countdown now — restore the previous
   * clipboard content rather than leaving the secret behind (§7.4; on
   * Wayland our offer dies with the process anyway). */
  clip_disarm (self, TRUE);
  self->toasts = NULL;
  g_clear_pointer (&self->entry, passfl_entry_free);
  G_OBJECT_CLASS (passfl_entry_view_parent_class)->dispose (obj);
}

static void
passfl_entry_view_class_init (PassflEntryViewClass *klass)
{
  G_OBJECT_CLASS (klass)->dispose = passfl_entry_view_dispose;
}

static void
passfl_entry_view_init (PassflEntryView *self)
{
  GtkWidget *scrolled = gtk_scrolled_window_new ();
  GtkWidget *clamp = adw_clamp_new ();

  gtk_orientable_set_orientation (GTK_ORIENTABLE (self),
                                  GTK_ORIENTATION_VERTICAL);

  self->stack = GTK_STACK (gtk_stack_new ());
  gtk_widget_set_vexpand (GTK_WIDGET (self->stack), TRUE);

  self->status = ADW_STATUS_PAGE (adw_status_page_new ());
  gtk_stack_add_named (self->stack, GTK_WIDGET (self->status), "status");

  self->groups_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 18);
  gtk_widget_set_margin_top (self->groups_box, 18);
  gtk_widget_set_margin_bottom (self->groups_box, 18);
  gtk_widget_set_margin_start (self->groups_box, 12);
  gtk_widget_set_margin_end (self->groups_box, 12);
  adw_clamp_set_child (ADW_CLAMP (clamp), self->groups_box);
  gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scrolled), clamp);
  gtk_stack_add_named (self->stack, scrolled, "entry");

  gtk_box_append (GTK_BOX (self), GTK_WIDGET (self->stack));
  passfl_entry_view_show_placeholder (self);
}

GtkWidget *
passfl_entry_view_new (void)
{
  return g_object_new (PASSFL_TYPE_ENTRY_VIEW, NULL);
}
