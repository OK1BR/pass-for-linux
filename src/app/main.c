/* main.c — pass-for-linux GTK4/libadwaita front-end bootstrap.
 *
 * The store engine lives in src/engine/ and stays GLib-only (no GTK) so
 * it is testable headless; the window itself is window.c.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include <adwaita.h>

#include "window.h"

static void
on_activate (AdwApplication *app, gpointer user_data)
{
  (void) user_data;

  GtkWindow *win = gtk_application_get_active_window (GTK_APPLICATION (app));
  if (!win)
    win = GTK_WINDOW (passfl_window_new (app));
  gtk_window_present (win);
  /* TEMP repro hook: PASSFL_AUTOCLOSE_MS=N closes the window after N ms */
  const char *auto_ms = g_getenv ("PASSFL_AUTOCLOSE_MS");
  if (auto_ms)
    g_timeout_add_once ((guint) g_ascii_strtoull (auto_ms, NULL, 10),
                        (GSourceOnceFunc) gtk_window_close, win);
}

int
main (int argc, char **argv)
{
  AdwApplication *app =
      adw_application_new ("cz.ok1br.pass_for_linux",
                           G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);
  int status = g_application_run (G_APPLICATION (app), argc, argv);
  g_object_unref (app);
  return status;
}
