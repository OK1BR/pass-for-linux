/* entry-view.h — one decrypted entry: reveal, copy with clear timer (M1).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_ENTRY_VIEW_H
#define PASSFL_ENTRY_VIEW_H

#include <adwaita.h>

#include "crypto.h"
#include "entry.h"

G_BEGIN_DECLS

#define PASSFL_TYPE_ENTRY_VIEW (passfl_entry_view_get_type ())
G_DECLARE_FINAL_TYPE (PassflEntryView, passfl_entry_view, PASSFL, ENTRY_VIEW,
                      GtkBox)

GtkWidget *passfl_entry_view_new (void);

/* Toasts (copy feedback, the countdown) surface here. Borrowed. */
void passfl_entry_view_set_toast_overlay (PassflEntryView *self,
                                          AdwToastOverlay *toasts);

void passfl_entry_view_show_placeholder (PassflEntryView *self);
void passfl_entry_view_show_error (PassflEntryView *self, const char *name,
                                   const char *message);

/* Takes ownership of entry — wiped on replace and on dispose. */
void passfl_entry_view_show_entry (PassflEntryView *self, const char *name,
                                   PassflEntry *entry);

/* HOTP generated a code: the entry was rebuilt with the counter bumped
 * (content, transfer full) and must be written back and committed with
 * pass-otp's "Increment HOTP counter for <name>." message (M5). */
typedef void (*PassflEntryViewHotpFunc) (PassflSecBuf *content,
                                         gpointer user_data);
void passfl_entry_view_set_hotp_handler (PassflEntryView *self,
                                         PassflEntryViewHotpFunc func,
                                         gpointer user_data);

/* Hand the shown entry over (for the editor); the view falls back to
 * the placeholder. NULL when nothing is shown. */
PassflEntry *passfl_entry_view_steal_entry (PassflEntryView *self);

G_END_DECLS

#endif /* PASSFL_ENTRY_VIEW_H */
