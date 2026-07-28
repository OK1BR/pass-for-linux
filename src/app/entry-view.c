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
#include "otp.h"

#define MASK "••••••••••" /* fixed width — never leaks the real length */
#define DEFAULT_CLIP_TIME 45

struct _PassflEntryView {
  GtkBox parent_instance;

  AdwToastOverlay *toasts;   /* borrowed from the window */
  GtkStack *stack;           /* "status" | "entry" */
  AdwStatusPage *status;
  GtkWidget *groups_box;     /* rebuilt per entry */
  PassflEntry *entry;        /* owned; wiped on replace/dispose */

  GPtrArray *otp_rows;       /* OtpRow — live TOTP rows (M5) */
  guint otp_timer_id;
  PassflEntryViewHotpFunc hotp_func;
  gpointer hotp_user_data;

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

/* --- live OTP rows (M5) --------------------------------------------------- */

static GtkWidget *flat_button (const char *icon, const char *tooltip);

typedef struct {
  PassflOtp *otp;
  GtkWidget *row;          /* AdwActionRow, subtitle carries the code */
  GtkWidget *ring;         /* GtkDrawingArea countdown */
} OtpRow;

static void
otp_row_free (gpointer data)
{
  OtpRow *r = data;

  passfl_otp_free (r->otp);
  g_free (r);
}

static void
otp_row_update (OtpRow *r)
{
  GError *error = NULL;
  gint64 now = (gint64) (g_get_real_time () / G_USEC_PER_SEC);
  g_autofree char *code = passfl_otp_code (r->otp, now, &error);

  if (code == NULL)
    {
      adw_action_row_set_subtitle (ADW_ACTION_ROW (r->row),
                                   error != NULL ? error->message
                                                 : "cannot compute code");
      g_clear_error (&error);
      return;
    }
  adw_action_row_set_subtitle (ADW_ACTION_ROW (r->row), code);
  gtk_widget_queue_draw (r->ring);
}

static gboolean
otp_tick (gpointer data)
{
  PassflEntryView *self = data;

  for (guint i = 0; i < self->otp_rows->len; i++)
    otp_row_update (g_ptr_array_index (self->otp_rows, i));
  return G_SOURCE_CONTINUE;
}

/* countdown ring: the remaining fraction of the period as an arc */
static void
draw_ring (GtkDrawingArea *area, cairo_t *cr, int width, int height,
           gpointer data)
{
  OtpRow *r = data;
  gint64 now = (gint64) (g_get_real_time () / G_USEC_PER_SEC);
  guint period = passfl_otp_period (r->otp);
  guint remaining = passfl_otp_remaining (r->otp, now);
  double frac = (double) remaining / (double) period;
  double cx = width / 2.0, cy = height / 2.0;
  double radius = MIN (cx, cy) - 2.0;
  GdkRGBA color;

  gtk_widget_get_color (GTK_WIDGET (area), &color);
  cairo_set_line_width (cr, 3.0);
  gdk_cairo_set_source_rgba (cr, &(GdkRGBA) { color.red, color.green,
                                              color.blue, 0.25 });
  cairo_arc (cr, cx, cy, radius, 0, 2 * G_PI);
  cairo_stroke (cr);
  gdk_cairo_set_source_rgba (cr, &color);
  cairo_arc (cr, cx, cy, radius, -G_PI / 2,
             -G_PI / 2 + 2 * G_PI * frac);
  cairo_stroke (cr);
}

static void
on_copy_totp (GtkButton *button, gpointer data)
{
  PassflEntryView *self = data;
  OtpRow *r = g_object_get_data (G_OBJECT (button), "passfl-otp-row");
  GError *error = NULL;
  gint64 now = (gint64) (g_get_real_time () / G_USEC_PER_SEC);
  g_autofree char *code = NULL;

  if (r == NULL)
    return;
  code = passfl_otp_code (r->otp, now, &error);
  if (code == NULL)
    {
      g_clear_error (&error);
      return;
    }
  copy_timed (self, code); /* cleared like pass otp -c would */
}

static void
on_hotp_generate (GtkButton *button, gpointer data)
{
  PassflEntryView *self = data;
  PassflOtp *otp = g_object_get_data (G_OBJECT (button), "passfl-hotp");
  guint line_idx = GPOINTER_TO_UINT (
      g_object_get_data (G_OBJECT (button), "passfl-line"));
  GError *error = NULL;
  g_autofree char *code = NULL;
  g_autofree char *bumped = NULL;

  if (otp == NULL || self->entry == NULL)
    return;
  /* pass-otp: code at counter+1, then the entry is rewritten */
  code = passfl_otp_hotp_code (otp, passfl_otp_counter (otp) + 1, &error);
  if (code == NULL)
    {
      toast (self, "%s", error != NULL ? error->message : "HOTP failed");
      g_clear_error (&error);
      return;
    }
  copy_timed (self, code);

  if (self->hotp_func == NULL)
    return;
  bumped = passfl_otp_incremented_uri (otp);
  {
    guint n = passfl_entry_n_lines (self->entry);
    gsize total = 0;
    PassflSecBuf *content;
    char *p;

    for (guint i = 0; i < n; i++)
      total += strlen (i == line_idx
                           ? bumped
                           : passfl_entry_line (self->entry, i)) +
               1;
    if (!passfl_entry_final_newline (self->entry) && total > 0)
      total--;
    content = passfl_secbuf_new_sized (total);
    p = content->data;
    for (guint i = 0; i < n; i++)
      {
        const char *line = i == line_idx
            ? bumped
            : passfl_entry_line (self->entry, i);
        gsize len = strlen (line);

        memcpy (p, line, len);
        p += len;
        if (i + 1 < n || passfl_entry_final_newline (self->entry))
          *p++ = '\n';
      }
    self->hotp_func (content, self->hotp_user_data);
  }
}

static GtkWidget *
otp_code_row (PassflEntryView *self, PassflOtp *otp /* takes */,
              guint line_idx)
{
  GtkWidget *row = adw_action_row_new ();
  GtkWidget *copy = flat_button ("edit-copy-symbolic",
                                 "Copy code (cleared after the timer)");
  const char *who = passfl_otp_display (otp);

  adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row), FALSE);
  gtk_widget_add_css_class (row, "numeric");

  if (passfl_otp_type (otp) == PASSFL_OTP_TOTP)
    {
      OtpRow *r = g_new0 (OtpRow, 1);
      GtkWidget *ring = gtk_drawing_area_new ();

      adw_preferences_row_set_title (
          ADW_PREFERENCES_ROW (row),
          who != NULL ? who : "One-time code");
      r->otp = otp;
      r->row = row;
      r->ring = ring;
      gtk_drawing_area_set_content_width (GTK_DRAWING_AREA (ring), 22);
      gtk_drawing_area_set_content_height (GTK_DRAWING_AREA (ring), 22);
      gtk_widget_set_valign (ring, GTK_ALIGN_CENTER);
      gtk_drawing_area_set_draw_func (GTK_DRAWING_AREA (ring), draw_ring,
                                      r, NULL);
      g_object_set_data (G_OBJECT (copy), "passfl-otp-row", r);
      g_signal_connect (copy, "clicked", G_CALLBACK (on_copy_totp), self);
      adw_action_row_add_suffix (ADW_ACTION_ROW (row), ring);
      adw_action_row_add_suffix (ADW_ACTION_ROW (row), copy);
      g_ptr_array_add (self->otp_rows, r);
      otp_row_update (r);
    }
  else
    {
      GtkWidget *gen = gtk_button_new_with_label ("Generate");
      g_autofree char *sub = g_strdup_printf (
          "HOTP, counter %" G_GUINT64_FORMAT, passfl_otp_counter (otp));

      adw_preferences_row_set_title (
          ADW_PREFERENCES_ROW (row),
          who != NULL ? who : "One-time code");
      adw_action_row_set_subtitle (ADW_ACTION_ROW (row), sub);
      gtk_widget_add_css_class (gen, "flat");
      gtk_widget_set_valign (gen, GTK_ALIGN_CENTER);
      gtk_widget_set_tooltip_text (
          gen, "Copy the next code and bump the counter, like pass otp");
      g_object_set_data_full (G_OBJECT (gen), "passfl-hotp", otp,
                              (GDestroyNotify) passfl_otp_free);
      g_object_set_data (G_OBJECT (gen), "passfl-line",
                         GUINT_TO_POINTER (line_idx));
      g_signal_connect (gen, "clicked", G_CALLBACK (on_hotp_generate),
                        self);
      adw_action_row_add_suffix (ADW_ACTION_ROW (row), gen);
      g_object_unref (g_object_ref_sink (copy)); /* unused for hotp */
      copy = NULL;
    }
  return row;
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

  g_clear_handle_id (&self->otp_timer_id, g_source_remove);
  g_ptr_array_set_size (self->otp_rows, 0);
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
        {
          PassflOtp *otp = passfl_otp_parse (line, NULL);

          /* live code row (§9); unparseable URIs stay a masked secret */
          row = otp != NULL ? otp_code_row (self, otp, i)
                            : secret_row (self, "OTP secret", i);
        }
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
  if (self->otp_rows->len > 0)
    self->otp_timer_id = g_timeout_add_seconds (1, otp_tick, self);
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

void
passfl_entry_view_set_hotp_handler (PassflEntryView *self,
                                    PassflEntryViewHotpFunc func,
                                    gpointer user_data)
{
  g_return_if_fail (PASSFL_IS_ENTRY_VIEW (self));
  self->hotp_func = func;
  self->hotp_user_data = user_data;
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
  g_clear_handle_id (&self->otp_timer_id, g_source_remove);
  g_clear_pointer (&self->otp_rows, g_ptr_array_unref);
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

  self->otp_rows = g_ptr_array_new_with_free_func (otp_row_free);
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
