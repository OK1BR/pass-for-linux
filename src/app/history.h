/* history.h — per-entry git history dialog (M3, SPEC §9).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_HISTORY_H
#define PASSFL_HISTORY_H

#include <adwaita.h>

#include "crypto.h"

G_BEGIN_DECLS

#define PASSFL_TYPE_HISTORY (passfl_history_get_type ())
G_DECLARE_FINAL_TYPE (PassflHistory, passfl_history, PASSFL, HISTORY,
                      AdwDialog)

/* Called when the user restores a revision: content (transfer full, in
 * secure memory) is the entry's plaintext at that revision. The dialog
 * closes itself afterwards. */
typedef void (*PassflHistoryRestoreFunc) (const char *rel,
                                          PassflSecBuf *content,
                                          gpointer user_data);

/* Build the dialog for one entry; present with adw_dialog_present. */
AdwDialog *passfl_history_new (const char *store_dir, const char *rel,
                               PassflHistoryRestoreFunc on_restore,
                               gpointer user_data);

G_END_DECLS

#endif /* PASSFL_HISTORY_H */
