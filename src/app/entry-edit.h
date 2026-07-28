/* entry-edit.h — structured editor for one entry (M2, SPEC §9).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_ENTRY_EDIT_H
#define PASSFL_ENTRY_EDIT_H

#include <adwaita.h>

#include "crypto.h"
#include "entry.h"

G_BEGIN_DECLS

#define PASSFL_TYPE_ENTRY_EDIT (passfl_entry_edit_get_type ())
G_DECLARE_FINAL_TYPE (PassflEntryEdit, passfl_entry_edit, PASSFL, ENTRY_EDIT,
                      GtkBox)

GtkWidget *passfl_entry_edit_new (void);

/* Load the editor. entry NULL starts a new entry (the name row shows);
 * otherwise takes ownership of entry and edits under the fixed name. */
void passfl_entry_edit_begin (PassflEntryEdit *self, const char *name,
                              PassflEntry *entry);

/* For a new entry: the name typed by the user (stripped); "" when empty.
 * For an existing one: the name passed to begin. */
const char *passfl_entry_edit_name (PassflEntryEdit *self);
gboolean    passfl_entry_edit_is_new (PassflEntryEdit *self);

/* Assemble the current widget state into entry content (secure memory):
 * password line, metadata lines, the original final-newline convention
 * (new entries always end with one). Caller frees. */
PassflSecBuf *passfl_entry_edit_content (PassflEntryEdit *self);

G_END_DECLS

#endif /* PASSFL_ENTRY_EDIT_H */
