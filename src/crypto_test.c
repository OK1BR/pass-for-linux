/* crypto_test.c — M1 gate (pass-crypto-test): decrypt via GPGME against a
 * throwaway GNUPGHOME with a passphrase-less key.
 *
 * The test spawns gpg to build its fixture — that is the conformance
 * method of SPEC §1 (the app itself never spawns anything). The user's
 * real keyring and store are never touched: GNUPGHOME points at a temp
 * directory for the whole process.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"

#include <ftw.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#define TEST_UID "passfl-test <passfl@test.invalid>"
#define PLAINTEXT "hunter2\nurl: https://example.com\n"

static char *gnupghome;
static char *workdir;

static int
rmtree_cb (const char *path, const struct stat *sb, int typeflag,
           struct FTW *ftwbuf)
{
  (void) sb;
  (void) typeflag;
  (void) ftwbuf;
  return remove (path);
}

static void
rmtree (const char *path)
{
  nftw (path, rmtree_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static gboolean
run_gpg (const char *const *argv)
{
  gint status = -1;
  g_autofree char *out = NULL;
  g_autofree char *err = NULL;

  if (!g_spawn_sync (NULL, (char **) argv, NULL,
                     G_SPAWN_SEARCH_PATH, NULL, NULL,
                     &out, &err, &status, NULL))
    return FALSE;
  if (!g_spawn_check_wait_status (status, NULL))
    {
      g_test_message ("gpg failed: %s", err != NULL ? err : "?");
      return FALSE;
    }
  return TRUE;
}

static void
test_init (void)
{
  GError *error = NULL;

  g_assert_true (passfl_crypto_init (&error));
  g_assert_no_error (error);
}

static void
test_decrypt_roundtrip (void)
{
  GError *error = NULL;
  g_autofree char *plain_path = g_build_filename (workdir, "plain", NULL);
  g_autofree char *cipher_path =
      g_build_filename (workdir, "entry.gpg", NULL);
  const char *encrypt[] = {
    "gpg", "--batch", "--yes", "--quiet", "--trust-model", "always",
    "--compress-algo=none", "--no-encrypt-to",
    "-r", TEST_UID, "-o", cipher_path, "-e", plain_path, NULL,
  };
  PassflSecBuf *buf;

  g_assert_true (g_file_set_contents (plain_path, PLAINTEXT, -1, NULL));
  g_assert_true (run_gpg (encrypt));
  g_assert_cmpint (remove (plain_path), ==, 0);

  buf = passfl_crypto_decrypt_file (cipher_path, &error);
  g_assert_no_error (error);
  g_assert_nonnull (buf);
  g_assert_cmpuint (buf->len, ==, strlen (PLAINTEXT));
  g_assert_cmpstr (buf->data, ==, PLAINTEXT);
  passfl_secbuf_free (buf);
}

static void
test_decrypt_garbage (void)
{
  GError *error = NULL;
  g_autofree char *path = g_build_filename (workdir, "garbage.gpg", NULL);

  g_assert_true (g_file_set_contents (path, "this is not pgp", -1, NULL));
  g_assert_null (passfl_crypto_decrypt_file (path, &error));
  g_assert_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_DECRYPT);
  g_clear_error (&error);
}

static void
test_decrypt_missing (void)
{
  GError *error = NULL;
  g_autofree char *path = g_build_filename (workdir, "no-such.gpg", NULL);

  g_assert_null (passfl_crypto_decrypt_file (path, &error));
  g_assert_nonnull (error);
  g_clear_error (&error);
}

int
main (int argc, char **argv)
{
  int ret;
  GError *error = NULL;
  g_autofree char *gpg = g_find_program_in_path ("gpg");

  g_test_init (&argc, &argv, NULL);

  if (gpg == NULL)
    {
      g_test_skip ("gpg not installed — cannot build the fixture");
      return g_test_run ();
    }

  gnupghome = g_dir_make_tmp ("passfl-gnupg-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (gnupghome, 0700), ==, 0);
  workdir = g_dir_make_tmp ("passfl-crypto-XXXXXX", &error);
  g_assert_no_error (error);

  /* Everything gpg/gpgme does below stays inside the throwaway home. */
  g_setenv ("GNUPGHOME", gnupghome, TRUE);

  {
    const char *keygen[] = {
      "gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
      "--passphrase", "", "--quick-generate-key", TEST_UID,
      "default", "default", "never", NULL,
    };
    g_assert_true (run_gpg (keygen));
  }

  g_test_add_func ("/crypto/init", test_init);
  g_test_add_func ("/crypto/decrypt-roundtrip", test_decrypt_roundtrip);
  g_test_add_func ("/crypto/decrypt-garbage", test_decrypt_garbage);
  g_test_add_func ("/crypto/decrypt-missing", test_decrypt_missing);

  ret = g_test_run ();

  {
    const char *kill_agent[] = {
      "gpgconf", "--kill", "gpg-agent", NULL,
    };
    run_gpg (kill_agent); /* do not leave an agent behind in the temp home */
  }
  rmtree (gnupghome);
  rmtree (workdir);
  g_free (gnupghome);
  g_free (workdir);
  return ret;
}
