/* recipient-view.h — who a subtree encrypts to (M4, SPEC §9).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_RECIPIENT_VIEW_H
#define PASSFL_RECIPIENT_VIEW_H

#include <adwaita.h>

G_BEGIN_DECLS

#define PASSFL_TYPE_RECIPIENT_VIEW (passfl_recipient_view_get_type ())
G_DECLARE_FINAL_TYPE (PassflRecipientView, passfl_recipient_view, PASSFL,
                      RECIPIENT_VIEW, AdwDialog)

/* Called after a successful "Re-encrypt subtree" (n entries rewritten),
 * so the window can refresh and toast. */
typedef void (*PassflRecipientReencFunc) (guint n_changed,
                                          gpointer user_data);

/* Build the dialog for the subtree containing entry rel (SPEC §9): the
 * winning .gpg-id, the resolved keys, the §4.10 mismatch warning for
 * the entry, and the re-encrypt action. */
AdwDialog *passfl_recipient_view_new (const char *store_dir,
                                      const char *rel,
                                      PassflRecipientReencFunc on_reenc,
                                      gpointer user_data);

G_END_DECLS

#endif /* PASSFL_RECIPIENT_VIEW_H */
