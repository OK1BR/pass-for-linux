/* crypto.c — GPGME wrapper and secure buffers, M1 (docs/SPEC.md §3, §7).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"

#include <gcrypt.h>
#include <gpgme.h>
#include <locale.h>
#include <string.h>

G_DEFINE_QUARK (passfl-crypto-error, passfl_crypto_error)

#define SECMEM_POOL (64 * 1024)

static gboolean
crypto_init_once (GError **error)
{
  gpgme_error_t err;

  if (gcry_check_version (NULL) == NULL)
    {
      g_set_error_literal (error, PASSFL_CRYPTO_ERROR,
                           PASSFL_CRYPTO_ERROR_INIT,
                           "libgcrypt version check failed");
      return FALSE;
    }
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_POOL, 0);
  gcry_control (GCRYCTL_AUTO_EXPAND_SECMEM, SECMEM_POOL, 0);
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
  if (err != GPG_ERR_NO_ERROR)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_INIT,
                   "No usable OpenPGP engine: %s", gpgme_strerror (err));
      return FALSE;
    }
  return TRUE;
}

gboolean
passfl_crypto_init (GError **error)
{
  static gsize once = 0;
  static gboolean ok = FALSE;
  static GError *saved = NULL;

  if (g_once_init_enter (&once))
    {
      ok = crypto_init_once (&saved);
      g_once_init_leave (&once, 1);
    }
  if (!ok && error != NULL && saved != NULL)
    *error = g_error_copy (saved);
  return ok;
}

PassflSecBuf *
passfl_secbuf_new (const char *data, gssize len)
{
  PassflSecBuf *buf;
  gsize n;

  g_return_val_if_fail (data != NULL || len <= 0, NULL);

  n = len < 0 ? strlen (data) : (gsize) len;
  buf = g_new0 (PassflSecBuf, 1);
  buf->data = gcry_malloc_secure (n + 1);
  if (buf->data == NULL) /* pool exhausted and expansion failed */
    g_error ("secure memory allocation of %" G_GSIZE_FORMAT " bytes failed",
             n + 1);
  if (n > 0)
    memcpy (buf->data, data, n);
  buf->data[n] = '\0';
  buf->len = n;
  return buf;
}

void
passfl_secbuf_free (PassflSecBuf *buf)
{
  if (buf == NULL)
    return;
  /* Secure memory is wiped by gcry_free; wipe once more ourselves so the
   * guarantee does not hinge on libgcrypt internals. */
  explicit_bzero (buf->data, buf->len + 1);
  gcry_free (buf->data);
  g_free (buf);
}

PassflSecBuf *
passfl_crypto_decrypt_file (const char *path, GError **error)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t cipher = NULL;
  gpgme_data_t plain = NULL;
  gpgme_error_t err;
  PassflSecBuf *buf = NULL;
  char *mem;
  size_t len;

  g_return_val_if_fail (path != NULL, NULL);

  if (!passfl_crypto_init (error))
    return NULL;

  err = gpgme_new (&ctx);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_data_new_from_file (&cipher, path, 1);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_data_new (&plain);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_op_decrypt (ctx, cipher, plain);

  if (err != GPG_ERR_NO_ERROR)
    {
      gpgme_err_code_t code = gpgme_err_code (err);
      gboolean cancelled = code == GPG_ERR_CANCELED ||
                           code == GPG_ERR_FULLY_CANCELED;

      g_set_error (error, PASSFL_CRYPTO_ERROR,
                   cancelled ? PASSFL_CRYPTO_ERROR_CANCELLED
                             : PASSFL_CRYPTO_ERROR_DECRYPT,
                   "Cannot decrypt '%s': %s", path, gpgme_strerror (err));
      goto out;
    }

  /* GPGME's buffer is ordinary heap — copy to secure memory and wipe it
   * (SPEC §7.2). */
  mem = gpgme_data_release_and_get_mem (plain, &len);
  plain = NULL;
  if (mem == NULL)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_DECRYPT,
                   "Cannot read decrypted data for '%s'", path);
      goto out;
    }
  buf = passfl_secbuf_new (mem, (gssize) len);
  explicit_bzero (mem, len);
  gpgme_free (mem);

out:
  if (plain != NULL)
    gpgme_data_release (plain);
  if (cipher != NULL)
    gpgme_data_release (cipher);
  if (ctx != NULL)
    gpgme_release (ctx);
  return buf;
}
