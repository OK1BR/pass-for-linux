/* generate.h — password generation (M2, SPEC §4.8).
 *
 * Reproduces pass's `tr -dc SET < /dev/urandom | head -c N` (lines
 * 19–21, 538): the SET syntax supports the POSIX classes in the C
 * locale, a-b ranges and literal characters; sampling is rejection from
 * getrandom(2) — never modulo over a raw byte, which would skew the
 * distribution toward the low end of the alphabet.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_GENERATE_H
#define PASSFL_GENERATE_H

#include <glib.h>

#include "crypto.h"

G_BEGIN_DECLS

#define PASSFL_GENERATE_ERROR passfl_generate_error_quark ()
GQuark passfl_generate_error_quark (void);

typedef enum {
  PASSFL_GENERATE_ERROR_SET,     /* charset expands to nothing */
  PASSFL_GENERATE_ERROR_RANDOM,  /* getrandom(2) failed */
} PassflGenerateError;

/* Expand a tr-style SET ("[:punct:][:alnum:]", "a-z0-9#@", …) into the
 * unique characters it contains, C locale, ASCII only. The alphabet is
 * not a secret — ordinary heap, caller frees. NULL + error when the set
 * is empty or malformed. */
char *passfl_generate_expand_set (const char *set, GError **error);

/* length 0 means $PASSWORD_STORE_GENERATED_LENGTH or 25. The alphabet
 * comes from $PASSWORD_STORE_CHARACTER_SET[_NO_SYMBOLS] or the §4.8
 * defaults. Returns the password in secure memory. */
PassflSecBuf *passfl_generate_password (guint length, gboolean no_symbols,
                                        GError **error);

G_END_DECLS

#endif /* PASSFL_GENERATE_H */
