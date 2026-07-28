/* recipients.h — who a subtree encrypts to: .gpg-id resolution (SPEC §2.2).
 *
 * Faithful to pass 1.7.4 set_gpg_recipients (lines 70–99): the environment
 * variable PASSWORD_STORE_KEY, when set, is the whole answer and no file is
 * consulted; otherwise walk from the entry's directory up to the store root
 * and the first .gpg-id found wins — a nested one fully overrides its
 * ancestors, never merges. No .gpg-id up to and including the root means
 * the store is uninitialised, a hard error. Signature verification of
 * .gpg-id (§2.4) needs GPGME and lands with the crypto milestone.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_RECIPIENTS_H
#define PASSFL_RECIPIENTS_H

#include <glib.h>

G_BEGIN_DECLS

#define PASSFL_RECIPIENTS_ERROR passfl_recipients_error_quark ()
GQuark passfl_recipients_error_quark (void);

typedef enum {
  PASSFL_RECIPIENTS_ERROR_UNINITIALIZED, /* no .gpg-id up to the root */
  PASSFL_RECIPIENTS_ERROR_SNEAKY_PATH,   /* ".." component (SPEC §2.5) */
  PASSFL_RECIPIENTS_ERROR_READ,          /* .gpg-id exists but unreadable */
} PassflRecipientsError;

/* Recipients for entries under root/dir_rel ("" is the root itself; for
 * entry "social/github" pass "social"). dir_rel need not exist on disk —
 * the walk only tests for .gpg-id files, exactly like pass. Returns a
 * NULL-terminated vector, caller frees with g_strfreev; it may be empty
 * when the winning .gpg-id holds nothing (pass behaves the same). When
 * gpg_id_file is non-NULL it receives the path of the .gpg-id that
 * decided, or NULL when PASSWORD_STORE_KEY did. */
GStrv passfl_recipients_resolve (const char *root, const char *dir_rel,
                                 char **gpg_id_file, GError **error);

/* Parse .gpg-id content (lines 102–107): one recipient per line, '#'
 * starts a comment, surrounding whitespace is trimmed, blank lines are
 * skipped. Internal whitespace ("Full Name <mail>") is preserved. */
GStrv passfl_gpg_id_parse (const char *content);

/* Expand gpg group names (§4.9): a recipient that matches a `group
 * name=members…` line in gpg.conf is replaced by its members — the
 * native equivalent of pass's `--list-config group` step (line 112,
 * §4.10 step 2). Non-group recipients pass through. Caller frees. */
GStrv passfl_recipients_expand_groups (const char *const *recipients);

G_END_DECLS

#endif /* PASSFL_RECIPIENTS_H */
