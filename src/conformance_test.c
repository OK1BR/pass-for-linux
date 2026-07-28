/* conformance_test.c — M2 gate (pass-conformance-test): the SPEC §1 rig.
 *
 * Two identical throwaway stores; every write runs through our engine on
 * store A and through the real `pass` script on store B, then trees,
 * file modes, decrypted content and OpenPGP packet shapes are compared.
 * Spawning pass/gpg here is the point of the rig — the app itself never
 * spawns anything. Everything lives in a temp GNUPGHOME and temp stores;
 * the user's keyring and store are never touched.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"
#include "generate.h"
#include "store.h"

#include <ftw.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define UID_MAIN "passfl-conf <conf@passfl.invalid>"
#define UID_OTHER "passfl-other <other@passfl.invalid>"
#define CONTENT "hunter2\nurl: https://example.com\nuser: rfa\n"

static char *gnupghome;
static char *store_a; /* operated by the engine */
static char *store_b; /* operated by pass */
static char *fpr_main;
static char *fpr_other;

/* --- helpers -------------------------------------------------------------- */

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

/* Run argv; env gets PASSWORD_STORE_DIR=dir when dir is non-NULL. */
static gboolean
run (const char *const *argv, const char *dir, char **out)
{
  g_auto (GStrv) env = g_get_environ ();
  gint status = -1;
  g_autofree char *err = NULL;
  char *stdout_buf = NULL;
  gboolean ok;

  if (dir != NULL)
    env = g_environ_setenv (env, "PASSWORD_STORE_DIR", dir, TRUE);
  if (!g_spawn_sync (NULL, (char **) argv, env, G_SPAWN_SEARCH_PATH, NULL,
                     NULL, &stdout_buf, &err, &status, NULL))
    return FALSE;
  ok = g_spawn_check_wait_status (status, NULL);
  if (!ok)
    g_test_message ("command failed: %s\n%s", argv[0],
                    err != NULL ? err : "");
  if (out != NULL)
    *out = stdout_buf;
  else
    g_free (stdout_buf);
  return ok;
}

/* printf "$CONTENT" | pass <args…>, via sh to feed stdin. */
static gboolean
pass_stdin (const char *dir, const char *content, const char *pass_args)
{
  g_autofree char *cmd =
      g_strdup_printf ("printf '%%s' \"$PASSFL_STDIN\" | pass %s", pass_args);
  const char *argv[] = { "sh", "-c", cmd, NULL };
  g_auto (GStrv) env = g_get_environ ();
  gint status = -1;
  g_autofree char *err = NULL;

  env = g_environ_setenv (env, "PASSWORD_STORE_DIR", dir, TRUE);
  env = g_environ_setenv (env, "PASSFL_STDIN", content, TRUE);
  if (!g_spawn_sync (NULL, (char **) argv, env, G_SPAWN_SEARCH_PATH, NULL,
                     NULL, NULL, &err, &status, NULL))
    return FALSE;
  if (!g_spawn_check_wait_status (status, NULL))
    {
      g_test_message ("pass %s failed:\n%s", pass_args,
                      err != NULL ? err : "");
      return FALSE;
    }
  return TRUE;
}

static char *
gpg_decrypt (const char *path)
{
  const char *argv[] = { "gpg", "--batch", "--quiet", "-d", path, NULL };
  char *out = NULL;

  g_assert_true (run (argv, NULL, &out));
  return out;
}

static guint
file_mode (const char *path)
{
  GStatBuf st;

  g_assert_cmpint (g_stat (path, &st), ==, 0);
  return st.st_mode & 0777;
}

static char *
entry_file (const char *store, const char *name)
{
  return g_strdup_printf ("%s/%s.gpg", store, name);
}

/* ":pubkey enc packet:" and friends — the observable shape of the file. */
static GStrv
packet_types (const char *path)
{
  const char *argv[] = { "gpg", "--batch", "--quiet", "--list-packets",
                         path, NULL };
  g_autofree char *out = NULL;
  g_auto (GStrv) lines = NULL;
  g_autoptr (GStrvBuilder) builder = g_strv_builder_new ();

  g_assert_true (run (argv, NULL, &out));
  lines = g_strsplit (out, "\n", -1);
  for (guint i = 0; lines[i] != NULL; i++)
    if (lines[i][0] == ':')
      {
        char *end = strstr (lines[i] + 1, ":");

        if (end != NULL)
          {
            g_autofree char *type =
                g_strndup (lines[i], (gsize) (end - lines[i]) + 1);
            g_strv_builder_add (builder, type);
          }
      }
  return g_strv_builder_end (builder);
}

/* --- tests ----------------------------------------------------------------- */

static void
test_insert (void)
{
  GError *error = NULL;
  g_autofree char *file_a = entry_file (store_a, "web/login");
  g_autofree char *file_b = entry_file (store_b, "web/login");
  g_autofree char *dec_a = NULL;
  g_autofree char *dec_b = NULL;
  g_autofree char *dir_a = g_build_filename (store_a, "web", NULL);
  g_autofree char *dir_b = g_build_filename (store_b, "web", NULL);

  g_assert_true (passfl_store_write_entry (store_a, "web/login", CONTENT,
                                           strlen (CONTENT), &error));
  g_assert_no_error (error);
  g_assert_true (pass_stdin (store_b, CONTENT, "insert -m -f web/login"));

  dec_a = gpg_decrypt (file_a);
  dec_b = gpg_decrypt (file_b);
  g_assert_cmpstr (dec_a, ==, CONTENT);
  g_assert_cmpstr (dec_b, ==, CONTENT);

  g_assert_cmpuint (file_mode (file_a), ==, file_mode (file_b));
  g_assert_cmpuint (file_mode (file_a), ==, 0600);
  g_assert_cmpuint (file_mode (dir_a), ==, file_mode (dir_b));
  g_assert_cmpuint (file_mode (dir_a), ==, 0700);
}

static void
test_overwrite (void)
{
  GError *error = NULL;
  const char *new_content = "changed-password\nurl: https://example.com\n";
  g_autofree char *file_a = entry_file (store_a, "web/login");
  g_autofree char *dec_a = NULL;

  g_assert_true (passfl_store_write_entry (store_a, "web/login", new_content,
                                           strlen (new_content), &error));
  g_assert_no_error (error);
  dec_a = gpg_decrypt (file_a);
  g_assert_cmpstr (dec_a, ==, new_content);
  g_assert_cmpuint (file_mode (file_a), ==, 0600);
}

static void
test_umask (void)
{
  GError *error = NULL;
  g_autofree char *file_a = entry_file (store_a, "open/x");
  g_autofree char *file_b = entry_file (store_b, "open/x");
  g_autofree char *dir_a = g_build_filename (store_a, "open", NULL);
  g_autofree char *dir_b = g_build_filename (store_b, "open", NULL);

  g_setenv ("PASSWORD_STORE_UMASK", "022", TRUE);
  g_assert_true (passfl_store_write_entry (store_a, "open/x", "x\n", 2,
                                           &error));
  g_assert_no_error (error);
  g_assert_true (pass_stdin (store_b, "x\n", "insert -m -f open/x"));
  g_unsetenv ("PASSWORD_STORE_UMASK");

  g_assert_cmpuint (file_mode (file_a), ==, file_mode (file_b));
  g_assert_cmpuint (file_mode (file_a), ==, 0644);
  g_assert_cmpuint (file_mode (dir_a), ==, file_mode (dir_b));
  g_assert_cmpuint (file_mode (dir_a), ==, 0755);
}

static void
test_rm (void)
{
  GError *error = NULL;
  const char *rm_argv[] = { "pass", "rm", "-f", "web/login", NULL };
  g_autofree char *dir_a = g_build_filename (store_a, "web", NULL);
  g_autofree char *dir_b = g_build_filename (store_b, "web", NULL);

  g_assert_true (passfl_store_delete_entry (store_a, "web/login", &error));
  g_assert_no_error (error);
  g_assert_true (run (rm_argv, store_b, NULL));

  /* entry gone, empty parent pruned — on both sides; roots intact */
  g_assert_false (passfl_store_entry_exists (store_a, "web/login"));
  g_assert_false (g_file_test (dir_a, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (dir_b, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_test (store_a, G_FILE_TEST_IS_DIR));

  /* deleting a missing entry mirrors pass's error */
  g_assert_false (passfl_store_delete_entry (store_a, "web/login", &error));
  g_assert_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_NOT_FOUND);
  g_clear_error (&error);
}

static void
test_generate_shape (void)
{
  GError *error = NULL;
  g_autofree char *alphabet =
      passfl_generate_expand_set ("[:punct:][:alnum:]", NULL);
  const char *gen_argv[] = { "pass", "generate", "-f", "gen/site", "20",
                             NULL };
  g_autofree char *file_b = entry_file (store_b, "gen/site");
  g_autofree char *dec_b = NULL;
  g_auto (GStrv) lines = NULL;
  PassflSecBuf *ours = passfl_generate_password (20, FALSE, &error);

  g_assert_no_error (error);
  g_assert_cmpuint (ours->len, ==, 20);
  for (gsize i = 0; i < ours->len; i++)
    g_assert_nonnull (strchr (alphabet, ours->data[i]));
  passfl_secbuf_free (ours);

  /* the same predicate must hold for what pass generates */
  g_assert_true (run (gen_argv, store_b, NULL));
  dec_b = gpg_decrypt (file_b);
  lines = g_strsplit (dec_b, "\n", 2);
  g_assert_cmpuint (strlen (lines[0]), ==, 20);
  for (const char *c = lines[0]; *c != '\0'; c++)
    g_assert_nonnull (strchr (alphabet, *c));
}

static void
test_packets (void)
{
  GError *error = NULL;
  g_autofree char *conf = g_build_filename (gnupghome, "gpg.conf", NULL);
  g_autofree char *conf_content =
      g_strdup_printf ("encrypt-to %s\ncompress-algo 2\n", fpr_other);
  g_autofree char *file_a = entry_file (store_a, "pkt/x");
  g_autofree char *file_b = entry_file (store_b, "pkt/x");
  g_auto (GStrv) types_a = NULL;
  g_auto (GStrv) types_b = NULL;
  guint enc_a = 0, enc_b = 0;

  /* A gpg.conf that would add a recipient and compression: pass shields
   * itself with --no-encrypt-to --compress-algo=none (line 9), the
   * engine with the equivalent GPGME flags — outputs must match. */
  g_assert_true (g_file_set_contents (conf, conf_content, -1, NULL));

  g_assert_true (passfl_store_write_entry (store_a, "pkt/x", "s\n", 2,
                                           &error));
  g_assert_no_error (error);
  g_assert_true (pass_stdin (store_b, "s\n", "insert -m -f pkt/x"));
  g_assert_cmpint (g_remove (conf), ==, 0);

  types_a = packet_types (file_a);
  types_b = packet_types (file_b);
  g_assert_cmpuint (g_strv_length (types_a), ==, g_strv_length (types_b));
  for (guint i = 0; types_a[i] != NULL; i++)
    {
      g_assert_cmpstr (types_a[i], ==, types_b[i]);
      g_assert_null (strstr (types_a[i], "compressed"));
      if (strstr (types_a[i], "pubkey enc") != NULL)
        enc_a++;
      if (strstr (types_b[i], "pubkey enc") != NULL)
        enc_b++;
    }
  /* exactly one recipient — encrypt-to did not leak in */
  g_assert_cmpuint (enc_a, ==, 1);
  g_assert_cmpuint (enc_b, ==, 1);
}

static void
test_signed_gpg_id (void)
{
  GError *error = NULL;
  g_autofree char *gpg_id = g_build_filename (store_a, ".gpg-id", NULL);
  g_autofree char *sig = g_strconcat (gpg_id, ".sig", NULL);
  g_autofree char *orig = NULL;
  g_autofree char *lower = g_ascii_strdown (fpr_main, -1);
  const char *sign_argv[] = { "gpg", "--batch", "--yes", "--detach-sign",
                              "-u", fpr_main, "-o", sig, gpg_id, NULL };

  g_assert_true (g_file_get_contents (gpg_id, &orig, NULL, NULL));
  g_assert_true (run (sign_argv, NULL, NULL));

  /* valid signature, allowed fingerprint → write succeeds */
  g_setenv ("PASSWORD_STORE_SIGNING_KEY", fpr_main, TRUE);
  g_assert_true (passfl_store_write_entry (store_a, "signed/ok", "x\n", 2,
                                           &error));
  g_assert_no_error (error);

  /* tampered .gpg-id → hard failure */
  {
    g_autofree char *tampered = g_strconcat (orig, "# tampered\n", NULL);

    g_assert_true (g_file_set_contents (gpg_id, tampered, -1, NULL));
    g_assert_false (passfl_store_write_entry (store_a, "signed/bad", "x\n",
                                              2, &error));
    g_assert_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_VERIFY);
    g_clear_error (&error);
    g_assert_true (g_file_set_contents (gpg_id, orig, -1, NULL));
  }

  /* signer not in the allowed list → failure */
  g_setenv ("PASSWORD_STORE_SIGNING_KEY", fpr_other, TRUE);
  g_assert_false (passfl_store_write_entry (store_a, "signed/bad", "x\n", 2,
                                            &error));
  g_assert_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_VERIFY);
  g_clear_error (&error);

  /* lowercase fingerprint is malformed per line 65 — skipped, so fails */
  g_setenv ("PASSWORD_STORE_SIGNING_KEY", lower, TRUE);
  g_assert_false (passfl_store_write_entry (store_a, "signed/bad", "x\n", 2,
                                            &error));
  g_assert_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_VERIFY);
  g_clear_error (&error);

  /* missing signature file → failure; and pass agrees */
  g_setenv ("PASSWORD_STORE_SIGNING_KEY", fpr_main, TRUE);
  g_assert_cmpint (g_remove (sig), ==, 0);
  g_assert_false (passfl_store_write_entry (store_a, "signed/bad", "x\n", 2,
                                            &error));
  g_assert_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_VERIFY);
  g_clear_error (&error);
  g_assert_false (pass_stdin (store_b, "x\n", "insert -m -f signed/bad"));

  g_unsetenv ("PASSWORD_STORE_SIGNING_KEY");
  g_assert_true (passfl_store_delete_entry (store_a, "signed/ok", NULL));
}

static void
test_gpg_opts_refused (void)
{
  GError *error = NULL;

  g_setenv ("PASSWORD_STORE_GPG_OPTS", "--armor", TRUE);
  g_assert_false (passfl_store_write_entry (store_a, "opts/x", "x\n", 2,
                                            &error));
  g_assert_error (error, PASSFL_CRYPTO_ERROR, PASSFL_CRYPTO_ERROR_GPG_OPTS);
  g_clear_error (&error);
  g_unsetenv ("PASSWORD_STORE_GPG_OPTS");
}

static void
test_uninitialised_write (void)
{
  GError *error = NULL;
  g_autofree char *bare = g_dir_make_tmp ("passfl-bare-XXXXXX", NULL);

  g_assert_false (passfl_store_write_entry (bare, "x", "x\n", 2, &error));
  g_assert_nonnull (error); /* "You must run: pass init" (§2.2 step 3) */
  g_clear_error (&error);
  rmtree (bare); /* bare is g_autofree */
}

/* --- main ------------------------------------------------------------------ */

static char *
key_fpr (const char *uid)
{
  const char *argv[] = { "gpg", "--batch", "--with-colons", "--list-keys",
                         uid, NULL };
  g_autofree char *out = NULL;
  g_auto (GStrv) lines = NULL;

  g_assert_true (run (argv, NULL, &out));
  lines = g_strsplit (out, "\n", -1);
  for (guint i = 0; lines[i] != NULL; i++)
    if (g_str_has_prefix (lines[i], "fpr:"))
      {
        g_auto (GStrv) f = g_strsplit (lines[i], ":", -1);

        return g_strdup (f[9]);
      }
  g_assert_not_reached ();
}

int
main (int argc, char **argv)
{
  int ret;
  GError *error = NULL;
  g_autofree char *gpg = g_find_program_in_path ("gpg");
  g_autofree char *pass = g_find_program_in_path ("pass");

  g_test_init (&argc, &argv, NULL);

  if (gpg == NULL || pass == NULL)
    {
      g_test_skip ("gpg or pass not installed");
      return g_test_run ();
    }

  gnupghome = g_dir_make_tmp ("passfl-conf-gnupg-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (gnupghome, 0700), ==, 0);
  g_setenv ("GNUPGHOME", gnupghome, TRUE);
  store_a = g_dir_make_tmp ("passfl-conf-a-XXXXXX", &error);
  g_assert_no_error (error);
  store_b = g_dir_make_tmp ("passfl-conf-b-XXXXXX", &error);
  g_assert_no_error (error);

  {
    const char *gen1[] = { "gpg", "--batch", "--quiet", "--pinentry-mode",
                           "loopback", "--passphrase", "",
                           "--quick-generate-key", UID_MAIN, "default",
                           "default", "never", NULL };
    const char *gen2[] = { "gpg", "--batch", "--quiet", "--pinentry-mode",
                           "loopback", "--passphrase", "",
                           "--quick-generate-key", UID_OTHER, "default",
                           "default", "never", NULL };
    const char *init_a[] = { "pass", "init", UID_MAIN, NULL };
    const char *init_b[] = { "pass", "init", UID_MAIN, NULL };

    g_assert_true (run (gen1, NULL, NULL));
    g_assert_true (run (gen2, NULL, NULL));
    fpr_main = key_fpr (UID_MAIN);
    fpr_other = key_fpr (UID_OTHER);
    g_assert_true (run (init_a, store_a, NULL));
    g_assert_true (run (init_b, store_b, NULL));
  }

  g_test_add_func ("/conformance/insert", test_insert);
  g_test_add_func ("/conformance/overwrite", test_overwrite);
  g_test_add_func ("/conformance/umask", test_umask);
  g_test_add_func ("/conformance/rm", test_rm);
  g_test_add_func ("/conformance/generate-shape", test_generate_shape);
  g_test_add_func ("/conformance/packets", test_packets);
  g_test_add_func ("/conformance/signed-gpg-id", test_signed_gpg_id);
  g_test_add_func ("/conformance/gpg-opts-refused", test_gpg_opts_refused);
  g_test_add_func ("/conformance/uninitialised-write",
                   test_uninitialised_write);

  ret = g_test_run ();

  {
    const char *kill_agent[] = { "gpgconf", "--kill", "gpg-agent", NULL };

    run (kill_agent, NULL, NULL);
  }
  rmtree (gnupghome);
  rmtree (store_a);
  rmtree (store_b);
  g_free (gnupghome);
  g_free (store_a);
  g_free (store_b);
  g_free (fpr_main);
  g_free (fpr_other);
  return ret;
}
