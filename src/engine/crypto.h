/* crypto.h — GPGME decryption and libgcrypt secure buffers (M1).
 *
 * Passphrases are gpg-agent's business: no passphrase callback is ever
 * installed, no pinentry of our own, the agent picks the dialog (SPEC §3).
 * Everything decrypted lives in gcry_malloc_secure() memory — mlocked,
 * wiped on free (SPEC §7.2). GPGME's own buffers are NOT secure memory:
 * decrypt copies the plaintext out and explicitly wipes what GPGME held.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_CRYPTO_H
#define PASSFL_CRYPTO_H

#include <glib.h>

G_BEGIN_DECLS

#define PASSFL_CRYPTO_ERROR passfl_crypto_error_quark ()
GQuark passfl_crypto_error_quark (void);

typedef enum {
  PASSFL_CRYPTO_ERROR_INIT,      /* GPGME/libgcrypt initialisation failed */
  PASSFL_CRYPTO_ERROR_DECRYPT,   /* gpg could not decrypt the file */
  PASSFL_CRYPTO_ERROR_CANCELLED, /* the user dismissed the agent's pinentry */
} PassflCryptoError;

/* Plaintext in secure memory. data is NUL-terminated on top of len bytes,
 * so it doubles as a C string when the content has no embedded NULs. */
typedef struct {
  char *data;
  gsize len;
} PassflSecBuf;

/* Copy len bytes (or strlen when len < 0) into a fresh secure buffer. */
PassflSecBuf *passfl_secbuf_new (const char *data, gssize len);

/* Wipe and release. NULL-safe. */
void passfl_secbuf_free (PassflSecBuf *buf);

/* One-time initialisation of GPGME and the libgcrypt secure-memory pool.
 * Idempotent; every other function here calls it as needed. */
gboolean passfl_crypto_init (GError **error);

/* Decrypt one store file. Blocks — run it from a worker thread; the first
 * call may sit in the agent's pinentry for as long as the user does. */
PassflSecBuf *passfl_crypto_decrypt_file (const char *path, GError **error);

G_END_DECLS

#endif /* PASSFL_CRYPTO_H */
