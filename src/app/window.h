/* window.h — the main window: store tree | entry view (M1).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_WINDOW_H
#define PASSFL_WINDOW_H

#include <adwaita.h>

G_BEGIN_DECLS

#define PASSFL_TYPE_WINDOW (passfl_window_get_type ())
G_DECLARE_FINAL_TYPE (PassflWindow, passfl_window, PASSFL, WINDOW,
                      AdwApplicationWindow)

GtkWidget *passfl_window_new (AdwApplication *app);

G_END_DECLS

#endif /* PASSFL_WINDOW_H */
