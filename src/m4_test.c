/* m4_test.c — M4 gate (pass-m4-test): mv/cp/init/re-encryption
 * conformance against the real pass on identical git stores.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"
#include "recipients.h"
#include "store.h"
#include "vcs.h"

#include <ftw.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#define UID_MAIN "passfl-m4 <m4@passfl.invalid>"
#define UID_OTHER "passfl-m4b <m4b@passfl.invalid>"

static char *gnupghome;
static char *store_a; /* engine */
static char *store_b; /* pass */
static char *fpr_main, *fpr_other;
static char *sub_main, *sub_other; /* long key IDs of the enc subkeys */

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
    g_test_message ("%s failed:\n%s", argv[0], err != NULL ? err : "");
  if (out != NULL)
    *out = stdout_buf;
  else
    g_free (stdout_buf);
  return ok;
}

static gboolean
pass_stdin (const char *dir, const char *content, const char *pass_args)
{
  g_autofree char *cmd =
      g_strdup_printf ("printf '%%s' \"$PASSFL_STDIN\" | pass %s",
                       pass_args);
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

/* log subjects with the absolute store path masked, so A and B compare */
static char *
log_subjects_masked (const char *store)
{
  const char *argv[] = { "git", "-C", store, "log", "--format=%s", NULL };
  g_autofree char *out = NULL;
  GString *masked;

  g_assert_true (run (argv, NULL, &out));
  masked = g_string_new (out);
  g_string_replace (masked, store, "STORE", 0);
  return g_string_free (masked, FALSE);
}

static char *
file_bytes (const char *path, gsize *len)
{
  char *data = NULL;

  g_assert_true (g_file_get_contents (path, &data, len, NULL));
  return data;
}

static void
assert_pkesk (const char *path, const char *keyid)
{
  GError *error = NULL;
  g_auto (GStrv) ids = passfl_crypto_file_keyids (path, &error);

  g_assert_no_error (error);
  g_assert_cmpuint (g_strv_length (ids), ==, 1);
  g_assert_cmpstr (ids[0], ==, keyid);
}

/* engine-side insert + commit, so both stores' logs stay in step */
static void
engine_insert_committed (const char *name, const char *content)
{
  GError *error = NULL;
  g_autofree char *path = passfl_store_entry_path (store_a, name, NULL);
  g_autofree char *msg = passfl_vcs_msg_insert (name);
  PassflVcs *vcs;

  g_assert_true (passfl_store_write_entry (store_a, name, content,
                                           strlen (content), &error));
  g_assert_no_error (error);
  vcs = passfl_vcs_open (store_a, path, NULL);
  g_assert_nonnull (vcs);
  g_assert_true (passfl_vcs_commit_file (vcs, path, msg, &error));
  g_assert_no_error (error);
  passfl_vcs_free (vcs);
}

/* --- tests ----------------------------------------------------------------- */

static void
test_mv_same_keys (void)
{
  GError *error = NULL;
  g_autofree char *src = g_build_filename (store_a, "plain", "x.gpg", NULL);
  g_autofree char *dst =
      g_build_filename (store_a, "plain", "y.gpg", NULL);
  g_autofree char *before = NULL;
  g_autofree char *after = NULL;
  gsize before_len = 0, after_len = 0;
  const char *mv_b[] = { "pass", "mv", "-f", "plain/x", "plain/y", NULL };
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;

  engine_insert_committed ("plain/x", "s\n");
  g_assert_true (pass_stdin (store_b, "s\n", "insert -m -f plain/x"));

  before = file_bytes (src, &before_len);
  g_assert_true (passfl_store_move (store_a, "plain/x", "plain/y", TRUE,
                                    NULL, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (run (mv_b, store_b, NULL));

  /* same recipients — the ciphertext moved untouched (§4.10 step 5) */
  after = file_bytes (dst, &after_len);
  g_assert_cmpmem (before, before_len, after, after_len);
  g_assert_false (g_file_test (src, G_FILE_TEST_EXISTS));

  log_a = log_subjects_masked (store_a);
  log_b = log_subjects_masked (store_b);
  g_assert_cmpstr (log_a, ==, log_b);
  g_assert_true (g_str_has_prefix (log_a, "Rename plain/x to plain/y.\n"));
}

static void
test_init_subtree (void)
{
  GError *error = NULL;
  const char *ids[] = { fpr_other, NULL };
  g_autofree char *init_args =
      g_strdup_printf ("init -p sub %s", fpr_other);
  const char *init_b[] = { "pass", "init", "-p", "sub", fpr_other, NULL };
  g_autofree char *gpg_id_a =
      g_build_filename (store_a, "sub", ".gpg-id", NULL);
  g_autofree char *gpg_id_b =
      g_build_filename (store_b, "sub", ".gpg-id", NULL);
  g_autofree char *content_a = NULL;
  g_autofree char *content_b = NULL;
  g_autofree char *entry_a =
      g_build_filename (store_a, "sub", "e.gpg", NULL);
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;
  g_autofree char *outside_before = NULL;
  g_autofree char *outside_after = NULL;
  gsize ob_len = 0, oa_len = 0;
  g_autofree char *outside =
      g_build_filename (store_a, "plain", "y.gpg", NULL);

  (void) init_args;

  /* an entry that will need re-encryption once sub gets its own key */
  engine_insert_committed ("sub/e", "v\n");
  g_assert_true (pass_stdin (store_b, "v\n", "insert -m -f sub/e"));
  assert_pkesk (entry_a, sub_main);

  outside_before = file_bytes (outside, &ob_len);
  g_assert_true (passfl_store_init_ids (store_a, "sub", ids, NULL, NULL,
                                        &error));
  g_assert_no_error (error);
  g_assert_true (run (init_b, store_b, NULL));

  g_assert_true (g_file_get_contents (gpg_id_a, &content_a, NULL, NULL));
  g_assert_true (g_file_get_contents (gpg_id_b, &content_b, NULL, NULL));
  g_assert_cmpstr (content_a, ==, content_b);

  /* the subtree re-encrypted to the new key, the rest untouched */
  assert_pkesk (entry_a, sub_other);
  outside_after = file_bytes (outside, &oa_len);
  g_assert_cmpmem (outside_before, ob_len, outside_after, oa_len);

  log_a = log_subjects_masked (store_a);
  log_b = log_subjects_masked (store_b);
  g_assert_cmpstr (log_a, ==, log_b);
  {
    g_autofree char *expected = g_strdup_printf (
        "Reencrypt password store using new GPG id %s (sub).\n"
        "Set GPG id to %s (sub).\n",
        fpr_other, fpr_other);

    g_assert_true (g_str_has_prefix (log_a, expected));
  }
}

static void
test_mv_across_boundary (void)
{
  GError *error = NULL;
  g_autofree char *moved =
      g_build_filename (store_a, "sub", "moved.gpg", NULL);
  const char *mv_b[] = { "pass", "mv", "-f", "plain/y", "sub/moved", NULL };
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;
  PassflSecBuf *plain;

  g_assert_true (passfl_store_move (store_a, "plain/y", "sub/moved", TRUE,
                                    NULL, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (run (mv_b, store_b, NULL));

  /* crossing into the key2 subtree re-encrypted the file (§4.9)… */
  assert_pkesk (moved, sub_other);
  /* …and it still decrypts to the original content */
  plain = passfl_crypto_decrypt_file (moved, &error);
  g_assert_no_error (error);
  g_assert_cmpstr (plain->data, ==, "s\n");
  passfl_secbuf_free (plain);

  log_a = log_subjects_masked (store_a);
  log_b = log_subjects_masked (store_b);
  g_assert_cmpstr (log_a, ==, log_b);
  g_assert_true (g_str_has_prefix (log_a,
                                   "Rename plain/y to sub/moved.\n"));
}

static void
test_cp_back (void)
{
  GError *error = NULL;
  g_autofree char *copy =
      g_build_filename (store_a, "copyback.gpg", NULL);
  const char *cp_b[] = { "pass", "cp", "-f", "sub/moved", "copyback",
                         NULL };
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;

  g_assert_true (passfl_store_copy (store_a, "sub/moved", "copyback", TRUE,
                                    NULL, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (run (cp_b, store_b, NULL));

  /* the copy landed under the root key again */
  assert_pkesk (copy, sub_main);
  log_a = log_subjects_masked (store_a);
  log_b = log_subjects_masked (store_b);
  g_assert_cmpstr (log_a, ==, log_b);
  g_assert_true (g_str_has_prefix (log_a,
                                   "Copy sub/moved to copyback.\n"));
}

static void
test_needs_reencrypt_and_fix (void)
{
  GError *error = NULL;
  gboolean needed = FALSE;
  g_autofree char *gpg_id =
      g_build_filename (store_a, "sub", ".gpg-id", NULL);
  g_autofree char *moved =
      g_build_filename (store_a, "sub", "moved.gpg", NULL);
  g_autofree char *sub_dir = g_build_filename (store_a, "sub", NULL);
  g_autofree char *line = g_strdup_printf ("%s\n", fpr_main);
  guint changed = 0;

  g_assert_true (passfl_store_entry_needs_reencrypt (store_a, "sub/moved",
                                                     &needed, &error));
  g_assert_no_error (error);
  g_assert_false (needed);

  /* hand-edit .gpg-id (what a CLI user could do without reencrypting) */
  g_assert_true (g_file_set_contents (gpg_id, line, -1, NULL));
  g_assert_true (passfl_store_entry_needs_reencrypt (store_a, "sub/moved",
                                                     &needed, &error));
  g_assert_true (needed);

  g_assert_true (passfl_store_reencrypt (store_a, sub_dir, NULL, NULL,
                                         &changed, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (changed, >=, 1);
  assert_pkesk (moved, sub_main);
  g_assert_true (passfl_store_entry_needs_reencrypt (store_a, "sub/moved",
                                                     &needed, &error));
  g_assert_false (needed);

  /* put key2 back for the deinit test */
  {
    g_autofree char *line2 = g_strdup_printf ("%s\n", fpr_other);

    g_assert_true (g_file_set_contents (gpg_id, line2, -1, NULL));
    g_assert_true (passfl_store_reencrypt (store_a, sub_dir, NULL, NULL,
                                           NULL, &error));
    g_assert_no_error (error);
  }
}

static void
test_deinit (void)
{
  GError *error = NULL;
  const char *init_b[] = { "pass", "init", "-p", "sub", "", NULL };
  g_autofree char *gpg_id_a =
      g_build_filename (store_a, "sub", ".gpg-id", NULL);
  g_autofree char *moved =
      g_build_filename (store_a, "sub", "moved.gpg", NULL);
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;

  g_assert_true (passfl_store_init_ids (store_a, "sub", NULL, NULL, NULL,
                                        &error));
  g_assert_no_error (error);
  g_assert_true (run (init_b, store_b, NULL));

  g_assert_false (g_file_test (gpg_id_a, G_FILE_TEST_EXISTS));
  /* the deinit tail re-encrypted the subtree back to the root key */
  assert_pkesk (moved, sub_main);

  log_a = log_subjects_masked (store_a);
  log_b = log_subjects_masked (store_b);
  g_assert_cmpstr (log_a, ==, log_b);
  /* including pass's double space when the id list is empty */
  g_assert_true (g_str_has_prefix (
      log_a, "Reencrypt password store using new GPG id  (sub).\n"
             "Deinitialize STORE/sub/.gpg-id (sub).\n"));
}

static void
test_signed_init (void)
{
  GError *error = NULL;
  const char *ids[] = { fpr_main, NULL };
  const char *init_b[] = { "pass", "init", "-p", "signedsub", fpr_main,
                           NULL };
  g_autofree char *sig_a =
      g_build_filename (store_a, "signedsub", ".gpg-id.sig", NULL);
  g_autofree char *gpg_id_a =
      g_build_filename (store_a, "signedsub", ".gpg-id", NULL);
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;

  g_setenv ("PASSWORD_STORE_SIGNING_KEY", fpr_main, TRUE);
  g_assert_true (passfl_store_init_ids (store_a, "signedsub", ids, NULL,
                                        NULL, &error));
  g_assert_no_error (error);
  g_assert_true (run (init_b, store_b, NULL));
  g_unsetenv ("PASSWORD_STORE_SIGNING_KEY");

  g_assert_true (g_file_test (sig_a, G_FILE_TEST_IS_REGULAR));
  /* our own §2.4 verifier accepts what we signed */
  g_setenv ("PASSWORD_STORE_SIGNING_KEY", fpr_main, TRUE);
  g_assert_true (passfl_crypto_verify_gpg_id (gpg_id_a, &error));
  g_assert_no_error (error);
  g_unsetenv ("PASSWORD_STORE_SIGNING_KEY");

  log_a = log_subjects_masked (store_a);
  log_b = log_subjects_masked (store_b);
  g_assert_cmpstr (log_a, ==, log_b);
  {
    g_autofree char *expected = g_strdup_printf (
        "Signing new GPG id with %s.", fpr_main);

    g_assert_nonnull (strstr (log_a, expected));
  }
}

static void
test_groups (void)
{
  GError *error = NULL;
  g_autofree char *conf = g_build_filename (gnupghome, "gpg.conf", NULL);
  g_autofree char *conf_content =
      g_strdup_printf ("group passflteam=%s\n", fpr_other);
  const char *ids[] = { "passflteam", NULL };
  const char *init_b[] = { "pass", "init", "-p", "grp", "passflteam",
                           NULL };
  g_autofree char *entry_a =
      g_build_filename (store_a, "grp", "g.gpg", NULL);
  gboolean needed = TRUE;

  g_assert_true (g_file_set_contents (conf, conf_content, -1, NULL));

  g_assert_true (passfl_store_init_ids (store_a, "grp", ids, NULL, NULL,
                                        &error));
  g_assert_no_error (error);
  g_assert_true (run (init_b, store_b, NULL));

  /* writing under the group-keyed subtree encrypts to the member key */
  engine_insert_committed ("grp/g", "g\n");
  assert_pkesk (entry_a, sub_other);
  g_assert_true (pass_stdin (store_b, "g\n", "insert -m -f grp/g"));

  /* and the §4.10 comparison understands the group — no false mismatch */
  g_assert_true (passfl_store_entry_needs_reencrypt (store_a, "grp/g",
                                                     &needed, &error));
  g_assert_no_error (error);
  g_assert_false (needed);

  g_assert_cmpint (g_remove (conf), ==, 0);
}

/* --- main ------------------------------------------------------------------ */

static void
key_ids (const char *uid, char **fpr, char **sub)
{
  const char *argv[] = { "gpg", "--batch", "--with-colons", "--list-keys",
                         uid, NULL };
  g_autofree char *out = NULL;
  g_auto (GStrv) lines = NULL;

  g_assert_true (run (argv, NULL, &out));
  lines = g_strsplit (out, "\n", -1);
  *fpr = NULL;
  *sub = NULL;
  for (guint i = 0; lines[i] != NULL; i++)
    {
      g_auto (GStrv) f = g_strsplit (lines[i], ":", -1);

      if (g_str_has_prefix (lines[i], "fpr:") && *fpr == NULL)
        *fpr = g_strdup (f[9]);
      if (g_str_has_prefix (lines[i], "sub:") &&
          strchr (f[11], 'e') != NULL && *sub == NULL)
        *sub = g_ascii_strup (f[4], -1);
    }
  g_assert_nonnull (*fpr);
  g_assert_nonnull (*sub);
}

static void
setup_store (const char *store)
{
  const char *git_init[] = { "git", "init", "-q", store, NULL };
  const char *cfg_name[] = { "git", "-C", store, "config", "user.name",
                             "passfl", NULL };
  const char *cfg_mail[] = { "git", "-C", store, "config", "user.email",
                             "m4@passfl.invalid", NULL };
  const char *cfg_nosign[] = { "git", "-C", store, "config",
                               "commit.gpgsign", "false", NULL };
  const char *cfg_nopass[] = { "git", "-C", store, "config",
                               "pass.signcommits", "false", NULL };
  const char *pass_init[] = { "pass", "init", UID_MAIN, NULL };
  const char *pass_git[] = { "pass", "git", "init", NULL };

  g_assert_true (run (git_init, NULL, NULL));
  g_assert_true (run (cfg_name, NULL, NULL));
  g_assert_true (run (cfg_mail, NULL, NULL));
  g_assert_true (run (cfg_nosign, NULL, NULL));
  g_assert_true (run (cfg_nopass, NULL, NULL));
  g_assert_true (run (pass_init, store, NULL));
  g_assert_true (run (pass_git, store, NULL));
}

int
main (int argc, char **argv)
{
  int ret;
  GError *error = NULL;
  g_autofree char *gpg = g_find_program_in_path ("gpg");
  g_autofree char *pass = g_find_program_in_path ("pass");
  g_autofree char *git = g_find_program_in_path ("git");

  g_test_init (&argc, &argv, NULL);

  if (gpg == NULL || pass == NULL || git == NULL)
    {
      g_test_skip ("gpg, pass or git not installed");
      return g_test_run ();
    }

  g_setenv ("GIT_CONFIG_GLOBAL", "/dev/null", TRUE);
  g_setenv ("GIT_CONFIG_NOSYSTEM", "1", TRUE);

  gnupghome = g_dir_make_tmp ("passfl-m4-gnupg-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (gnupghome, 0700), ==, 0);
  g_setenv ("GNUPGHOME", gnupghome, TRUE);
  store_a = g_dir_make_tmp ("passfl-m4-a-XXXXXX", &error);
  g_assert_no_error (error);
  store_b = g_dir_make_tmp ("passfl-m4-b-XXXXXX", &error);
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

    g_assert_true (run (gen1, NULL, NULL));
    g_assert_true (run (gen2, NULL, NULL));
    key_ids (UID_MAIN, &fpr_main, &sub_main);
    key_ids (UID_OTHER, &fpr_other, &sub_other);
  }
  setup_store (store_a);
  setup_store (store_b);

  g_test_add_func ("/m4/mv-same-keys", test_mv_same_keys);
  g_test_add_func ("/m4/init-subtree", test_init_subtree);
  g_test_add_func ("/m4/mv-across-boundary", test_mv_across_boundary);
  g_test_add_func ("/m4/cp-back", test_cp_back);
  g_test_add_func ("/m4/needs-reencrypt-and-fix",
                   test_needs_reencrypt_and_fix);
  g_test_add_func ("/m4/deinit", test_deinit);
  g_test_add_func ("/m4/signed-init", test_signed_init);
  g_test_add_func ("/m4/groups", test_groups);

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
  g_free (sub_main);
  g_free (sub_other);
  return ret;
}
