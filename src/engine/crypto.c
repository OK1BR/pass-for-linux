/* crypto.c — GPGME wrapper and secure buffers, M1 (docs/SPEC.md §3, §7).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"

#include <errno.h>
#include <gcrypt.h>
#include <glib/gstdio.h>
#include <gpgme.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

PassflSecBuf *
passfl_secbuf_new_sized (gsize len)
{
  PassflSecBuf *buf = g_new0 (PassflSecBuf, 1);

  buf->data = gcry_malloc_secure (len + 1);
  if (buf->data == NULL)
    g_error ("secure memory allocation of %" G_GSIZE_FORMAT " bytes failed",
             len + 1);
  memset (buf->data, 0, len + 1);
  buf->len = len;
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

/* what identifies the ciphertext source in error messages */
static PassflSecBuf *
decrypt_data (gpgme_data_t cipher /* consumed */, const char *what,
              GError **error)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t plain = NULL;
  gpgme_error_t err;
  PassflSecBuf *buf = NULL;
  char *mem;
  size_t len;

  err = gpgme_new (&ctx);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
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
                   "Cannot decrypt '%s': %s", what, gpgme_strerror (err));
      goto out;
    }

  /* GPGME's buffer is ordinary heap — copy to secure memory and wipe it
   * (SPEC §7.2). */
  mem = gpgme_data_release_and_get_mem (plain, &len);
  plain = NULL;
  if (mem == NULL)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_DECRYPT,
                   "Cannot read decrypted data for '%s'", what);
      goto out;
    }
  buf = passfl_secbuf_new (mem, (gssize) len);
  explicit_bzero (mem, len);
  gpgme_free (mem);

out:
  if (plain != NULL)
    gpgme_data_release (plain);
  gpgme_data_release (cipher);
  if (ctx != NULL)
    gpgme_release (ctx);
  return buf;
}

PassflSecBuf *
passfl_crypto_decrypt_file (const char *path, GError **error)
{
  gpgme_data_t cipher = NULL;
  gpgme_error_t err;

  g_return_val_if_fail (path != NULL, NULL);

  if (!passfl_crypto_init (error))
    return NULL;
  err = gpgme_data_new_from_file (&cipher, path, 1);
  if (err != GPG_ERR_NO_ERROR)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_DECRYPT,
                   "Cannot read '%s': %s", path, gpgme_strerror (err));
      return NULL;
    }
  return decrypt_data (cipher, path, error);
}

PassflSecBuf *
passfl_crypto_decrypt_mem (const char *data, gsize len, GError **error)
{
  gpgme_data_t cipher = NULL;
  gpgme_error_t err;

  g_return_val_if_fail (data != NULL, NULL);

  if (!passfl_crypto_init (error))
    return NULL;
  err = gpgme_data_new_from_mem (&cipher, data, len, 1);
  if (err != GPG_ERR_NO_ERROR)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_DECRYPT,
                   "Cannot read ciphertext: %s", gpgme_strerror (err));
      return NULL;
    }
  return decrypt_data (cipher, "git blob", error);
}

char *
passfl_crypto_sign_detached (const char *data, gsize len,
                             const char *signer, GError **error)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;
  gpgme_error_t err;
  char *mem = NULL;
  char *sig = NULL;
  size_t sig_len;

  g_return_val_if_fail (data != NULL, NULL);

  if (!passfl_crypto_init (error))
    return NULL;

  err = gpgme_new (&ctx);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
  if (err == GPG_ERR_NO_ERROR)
    gpgme_set_armor (ctx, 1);
  if (err == GPG_ERR_NO_ERROR && signer != NULL && *signer != '\0')
    {
      gpgme_key_t key = NULL;

      err = gpgme_get_key (ctx, signer, &key, 1);
      if (err == GPG_ERR_NO_ERROR)
        {
          err = gpgme_signers_add (ctx, key);
          gpgme_key_unref (key);
        }
    }
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_data_new_from_mem (&in, data, len, 0);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_data_new (&out);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_DETACH);

  if (err != GPG_ERR_NO_ERROR)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_ENCRYPT,
                   "Cannot sign commit: %s", gpgme_strerror (err));
      goto out;
    }

  mem = gpgme_data_release_and_get_mem (out, &sig_len);
  out = NULL;
  if (mem != NULL)
    {
      sig = g_strndup (mem, sig_len);
      gpgme_free (mem);
    }

out:
  if (in != NULL)
    gpgme_data_release (in);
  if (out != NULL)
    gpgme_data_release (out);
  if (ctx != NULL)
    gpgme_release (ctx);
  return sig;
}

/* --- encryption (M2) ------------------------------------------------------ */

/* 0666 & ~PASSWORD_STORE_UMASK — the mode pass's gpg -o would produce
 * under that umask (line 6). Modes are applied explicitly with fchmod so
 * the observable result never depends on the process umask. */
static mode_t
store_file_mode (void)
{
  const char *env = g_getenv ("PASSWORD_STORE_UMASK");
  guint um = 077;

  if (env != NULL && *env != '\0')
    {
      char *end = NULL;
      gulong v = strtoul (env, &end, 8);

      if (end != NULL && *end == '\0' && v <= 0777)
        um = (guint) v;
    }
  return (mode_t) (0666 & ~um);
}

/* First usable key gpg -r would pick for this string: not revoked, not
 * expired, not disabled, encryption-capable. */
static gpgme_key_t
lookup_recipient (gpgme_ctx_t ctx, const char *recipient, GError **error)
{
  gpgme_key_t key = NULL;
  gpgme_key_t found = NULL;
  gpgme_error_t err;

  err = gpgme_op_keylist_start (ctx, recipient, 0);
  while (err == GPG_ERR_NO_ERROR &&
         gpgme_op_keylist_next (ctx, &key) == GPG_ERR_NO_ERROR)
    {
      if (found == NULL && !key->revoked && !key->expired &&
          !key->disabled && key->can_encrypt)
        found = key; /* keep the ref */
      else
        gpgme_key_unref (key);
    }
  gpgme_op_keylist_end (ctx);

  if (found == NULL)
    g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_RECIPIENT,
                 "No usable key for recipient '%s' (gpg groups are not "
                 "supported yet)", recipient);
  return found;
}

/* Temp file next to the target, exact mode, fsync, rename over. The temp
 * name starts with a dot so a concurrent scan never lists it. */
static gboolean
atomic_write (const char *path, const char *data, size_t len,
              GError **error)
{
  g_autofree char *dir = g_path_get_dirname (path);
  g_autofree char *tmpl =
      g_build_filename (dir, ".passfl.tmp.XXXXXX", NULL);
  int fd = g_mkstemp (tmpl);
  gsize off = 0;

  if (fd < 0)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_ENCRYPT,
                   "Cannot create temporary file in '%s'", dir);
      return FALSE;
    }
  if (fchmod (fd, store_file_mode ()) != 0)
    goto fail;
  while (off < len)
    {
      gssize n = write (fd, data + off, len - off);

      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          goto fail;
        }
      off += (gsize) n;
    }
  if (fsync (fd) != 0 || close (fd) != 0)
    {
      fd = -1;
      goto fail;
    }
  fd = -1;
  if (rename (tmpl, path) != 0)
    goto fail;
  return TRUE;

fail:
  g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_ENCRYPT,
               "Cannot write '%s': %s", path, g_strerror (errno));
  if (fd >= 0)
    close (fd);
  unlink (tmpl); /* never leave the temp behind (cf. pass line 137) */
  return FALSE;
}

gboolean
passfl_crypto_encrypt_file (const char *path, const char *data, gsize len,
                            const char *const *recipients, GError **error)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t plain = NULL;
  gpgme_data_t cipher = NULL;
  gpgme_key_t *keys = NULL;
  guint n_keys = 0;
  gpgme_error_t err;
  gboolean ok = FALSE;
  const char *opts = g_getenv ("PASSWORD_STORE_GPG_OPTS");
  char *mem = NULL;
  size_t mem_len = 0;

  g_return_val_if_fail (path != NULL, FALSE);
  g_return_val_if_fail (data != NULL || len == 0, FALSE);
  g_return_val_if_fail (recipients != NULL, FALSE);

  if (!passfl_crypto_init (error))
    return FALSE;

  /* §3: the variable MUST be honoured — GPGME cannot forward arbitrary
   * CLI options, so honouring it means refusing to write differently
   * than pass would, not ignoring it. */
  if (opts != NULL && *opts != '\0')
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_GPG_OPTS,
                   "PASSWORD_STORE_GPG_OPTS is set ('%s') — the GUI cannot "
                   "pass gpg options through GPGME and will not write with "
                   "different options than pass would; use the CLI", opts);
      return FALSE;
    }

  if (recipients[0] == NULL)
    {
      g_set_error_literal (error, PASSFL_CRYPTO_ERROR,
                           PASSFL_CRYPTO_ERROR_RECIPIENT,
                           "No recipients to encrypt to");
      return FALSE;
    }

  err = gpgme_new (&ctx);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
  if (err != GPG_ERR_NO_ERROR)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_ENCRYPT,
                   "GPGME context: %s", gpgme_strerror (err));
      goto out;
    }

  for (n_keys = 0; recipients[n_keys] != NULL; n_keys++)
    ;
  keys = g_new0 (gpgme_key_t, n_keys + 1);
  for (guint i = 0; i < n_keys; i++)
    {
      keys[i] = lookup_recipient (ctx, recipients[i], error);
      if (keys[i] == NULL)
        goto out;
    }

  err = gpgme_data_new_from_mem (&plain, data, len, 0);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_data_new (&cipher);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_op_encrypt (ctx, keys,
                            GPGME_ENCRYPT_NO_ENCRYPT_TO |
                                GPGME_ENCRYPT_NO_COMPRESS,
                            plain, cipher);
  if (err != GPG_ERR_NO_ERROR)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_ENCRYPT,
                   "Cannot encrypt '%s': %s", path, gpgme_strerror (err));
      goto out;
    }

  mem = gpgme_data_release_and_get_mem (cipher, &mem_len);
  cipher = NULL;
  if (mem == NULL)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_ENCRYPT,
                   "Cannot read ciphertext for '%s'", path);
      goto out;
    }
  ok = atomic_write (path, mem, mem_len, error);

out:
  if (mem != NULL)
    gpgme_free (mem);
  if (plain != NULL)
    gpgme_data_release (plain);
  if (cipher != NULL)
    gpgme_data_release (cipher);
  if (keys != NULL)
    for (guint i = 0; keys[i] != NULL; i++)
      gpgme_key_unref (keys[i]);
  g_free (keys);
  if (ctx != NULL)
    gpgme_release (ctx);
  return ok;
}

/* --- signed .gpg-id (§2.4) ------------------------------------------------ */

gboolean
passfl_crypto_verify_gpg_id (const char *path, GError **error)
{
  const char *env = g_getenv ("PASSWORD_STORE_SIGNING_KEY");
  g_autofree char *sig_path = NULL;
  g_auto (GStrv) allowed = NULL;
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t sig = NULL;
  gpgme_data_t text = NULL;
  gpgme_verify_result_t result;
  gpgme_error_t err;
  gboolean found = FALSE;

  g_return_val_if_fail (path != NULL, FALSE);

  if (env == NULL || *env == '\0')
    return TRUE; /* verification not requested (line 60) */

  if (!passfl_crypto_init (error))
    return FALSE;

  sig_path = g_strconcat (path, ".sig", NULL);
  if (!g_file_test (sig_path, G_FILE_TEST_IS_REGULAR))
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_VERIFY,
                   "Signature for %s does not exist.", path);
      return FALSE;
    }

  err = gpgme_new (&ctx);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_data_new_from_file (&sig, sig_path, 1);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_data_new_from_file (&text, path, 1);
  if (err == GPG_ERR_NO_ERROR)
    err = gpgme_op_verify (ctx, sig, text, NULL);
  if (err != GPG_ERR_NO_ERROR)
    {
      g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_VERIFY,
                   "Signature for %s is invalid. (%s)", path,
                   gpgme_strerror (err));
      goto out;
    }

  /* pass accepts a fingerprint match on either the signing (sub)key or
   * the primary key (both fields of VALIDSIG, line 62); malformed
   * entries in the variable are skipped, so all-malformed fails. */
  allowed = g_strsplit_set (env, " \t\n", -1);
  result = gpgme_op_verify_result (ctx);
  for (gpgme_signature_t s = result != NULL ? result->signatures : NULL;
       s != NULL && !found; s = s->next)
    {
      gpgme_key_t key = NULL;
      const char *primary = NULL;

      if (gpgme_err_code (s->status) != GPG_ERR_NO_ERROR || s->fpr == NULL)
        continue;
      if (gpgme_get_key (ctx, s->fpr, &key, 0) == GPG_ERR_NO_ERROR &&
          key != NULL && key->subkeys != NULL)
        primary = key->subkeys->fpr;
      for (guint i = 0; allowed[i] != NULL && !found; i++)
        {
          const char *fpr = allowed[i];
          gboolean wellformed = strlen (fpr) == 40;

          for (const char *c = fpr; wellformed && *c != '\0'; c++)
            wellformed = g_ascii_isdigit (*c) ||
                         (*c >= 'A' && *c <= 'F');
          if (!wellformed)
            continue; /* line 65: skipped, never matched */
          if (strcmp (fpr, s->fpr) == 0 ||
              (primary != NULL && strcmp (fpr, primary) == 0))
            found = TRUE;
        }
      if (key != NULL)
        gpgme_key_unref (key);
    }

  if (!found)
    g_set_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_VERIFY,
                 "Signature for %s is invalid.", path);

out:
  if (sig != NULL)
    gpgme_data_release (sig);
  if (text != NULL)
    gpgme_data_release (text);
  if (ctx != NULL)
    gpgme_release (ctx);
  return found;
}
