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
  PASSFL_CRYPTO_ERROR_RECIPIENT, /* no usable key for a recipient string */
  PASSFL_CRYPTO_ERROR_ENCRYPT,   /* encryption or the atomic write failed */
  PASSFL_CRYPTO_ERROR_VERIFY,    /* .gpg-id signature check failed (§2.4) */
  PASSFL_CRYPTO_ERROR_GPG_OPTS,  /* PASSWORD_STORE_GPG_OPTS set — refused */
} PassflCryptoError;

/* Plaintext in secure memory. data is NUL-terminated on top of len bytes,
 * so it doubles as a C string when the content has no embedded NULs. */
typedef struct {
  char *data;
  gsize len;
} PassflSecBuf;

/* Copy len bytes (or strlen when len < 0) into a fresh secure buffer. */
PassflSecBuf *passfl_secbuf_new (const char *data, gssize len);

/* Zeroed secure buffer of len bytes (plus the NUL), for filling in. */
PassflSecBuf *passfl_secbuf_new_sized (gsize len);

/* Wipe and release. NULL-safe. */
void passfl_secbuf_free (PassflSecBuf *buf);

/* One-time initialisation of GPGME and the libgcrypt secure-memory pool.
 * Idempotent; every other function here calls it as needed. */
gboolean passfl_crypto_init (GError **error);

/* Decrypt one store file. Blocks — run it from a worker thread; the first
 * call may sit in the agent's pinentry for as long as the user does. */
PassflSecBuf *passfl_crypto_decrypt_file (const char *path, GError **error);

/* Encrypt data to recipients and atomically replace path: temp file in
 * the same directory with mode 0666 & ~PASSWORD_STORE_UMASK, fsync,
 * rename(2) (SPEC §7.3, §7.7). Reproduces pass's gpg invocation via
 * GPGME_ENCRYPT_NO_COMPRESS | GPGME_ENCRYPT_NO_ENCRYPT_TO (§3). Each
 * recipient string is whatever gpg -r accepts — key ID, fingerprint,
 * e-mail — except gpg groups, which fail loudly until M4 (§4.9). A set
 * PASSWORD_STORE_GPG_OPTS cannot be forwarded through GPGME, so writes
 * refuse rather than silently produce something else than pass would. */
gboolean passfl_crypto_encrypt_file (const char *path,
                                     const char *data, gsize len,
                                     const char *const *recipients,
                                     GError **error);

/* The §2.4 check, pass's verify_file (lines 59–68): with
 * PASSWORD_STORE_SIGNING_KEY set, <path>.sig must exist and carry a valid
 * signature whose signing or primary key fingerprint is one of the
 * 40-hex-uppercase fingerprints in that variable. TRUE when unset. */
gboolean passfl_crypto_verify_gpg_id (const char *path, GError **error);

G_END_DECLS

#endif /* PASSFL_CRYPTO_H */
