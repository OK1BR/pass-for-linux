/* entry.h — decrypted entry content: line 1 password + metadata (M1).
 *
 * There is no schema (SPEC §2.3): an entry is arbitrary UTF-8 text whose
 * first line is the password by convention. This module splits lines for
 * display and offers the community `key: value` reading as a hint only —
 * nothing is enforced, unknown lines round-trip untouched (the writer
 * lands in M2, final_newline is kept for it). All parsed content lives in
 * secure memory; line pointers point into it, never into ordinary heap.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_ENTRY_H
#define PASSFL_ENTRY_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct _PassflEntry PassflEntry;

/* Parse a decrypted buffer (copied into secure memory of its own). */
PassflEntry *passfl_entry_parse (const char *data, gsize len);
void         passfl_entry_free  (PassflEntry *entry);

/* Lines are 0-based here; pass(1) speaks 1-based (SPEC §4.2). A trailing
 * final newline does not count as an extra empty line. */
guint       passfl_entry_n_lines       (const PassflEntry *entry);
const char *passfl_entry_line          (const PassflEntry *entry, guint i);
gboolean    passfl_entry_final_newline (const PassflEntry *entry);

/* Line 0, or "" for an empty entry. Points into secure memory. */
const char *passfl_entry_password (const PassflEntry *entry);

/* Display hint: TRUE when line reads as `key: value` — key is everything
 * before the first ':', value skips the spaces after it. URI-shaped lines
 * ("https://…", "otpauth://…") are not key/value. Pointers point into
 * line; nothing is copied. */
gboolean passfl_entry_line_kv (const char *line, gsize *key_len,
                               const char **value);

/* TRUE for an otpauth://totp/ or otpauth://hotp/ line (pass-otp, §2.3).
 * Sensitive — it carries the OTP secret; the UI masks it like a password. */
gboolean passfl_entry_line_is_otp (const char *line);

G_END_DECLS

#endif /* PASSFL_ENTRY_H */
