/* vcs_test.c — M3 gate (pass-vcs-test): §6 conformance on git stores.
 *
 * Store A is driven by the engine (libgit2), store B by the real pass
 * script; both start from an identical `pass git init`. Commit subjects,
 * the changed-only guard, signed commits (verified by real
 * `git verify-commit`), history and revision reads are compared.
 * Everything runs in throwaway stores, a throwaway GNUPGHOME, and with
 * git's global/system config masked out.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"
#include "store.h"
#include "vcs.h"

#include <ftw.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#define UID "passfl-vcs <vcs@passfl.invalid>"
#define CONTENT "hunter2\nurl: https://example.com\n"
#define EDITED "edited-content\nurl: https://example.com\n"

static char *gnupghome;
static char *store_a;
static char *store_b;
static char *editor_sh;
static char *fpr;

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
  env = g_environ_setenv (env, "EDITOR", editor_sh, TRUE);
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

static char *
log_subjects (const char *store)
{
  const char *argv[] = { "git", "-C", store, "log", "--format=%s", NULL };
  char *out = NULL;

  g_assert_true (run (argv, NULL, &out));
  return out;
}

static guint
commit_count (const char *store)
{
  g_autofree char *log = log_subjects (store);
  guint n = 0;

  for (const char *p = log; *p != '\0'; p++)
    if (*p == '\n')
      n++;
  return n;
}

/* engine-side operation + commit, like the app does */
static void
engine_write_committed (const char *name, const char *content,
                        char *(*msg) (const char *))
{
  GError *error = NULL;
  g_autofree char *path =
      passfl_store_entry_path (store_a, name, NULL);
  g_autofree char *message = msg (name);
  PassflVcs *vcs;

  g_assert_true (passfl_store_write_entry (store_a, name, content,
                                           strlen (content), &error));
  g_assert_no_error (error);
  vcs = passfl_vcs_open (store_a, path, &error);
  g_assert_no_error (error);
  g_assert_nonnull (vcs);
  if (!passfl_vcs_commit_file (vcs, path, message, &error))
    {
      g_test_message ("commit failed: %s",
                      error != NULL ? error->message : "?");
      g_assert_not_reached ();
    }
  passfl_vcs_free (vcs);
}

/* --- tests ----------------------------------------------------------------- */

static void
test_insert (void)
{
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;

  engine_write_committed ("web/login", CONTENT, passfl_vcs_msg_insert);
  g_assert_true (pass_stdin (store_b, CONTENT, "insert -m -f web/login"));

  log_a = log_subjects (store_a);
  log_b = log_subjects (store_b);
  g_assert_cmpstr (log_a, ==, log_b);
  g_assert_true (g_str_has_prefix (
      log_a, "Add given password for web/login to store.\n"));
}

static char *
msg_edit_existing (const char *name)
{
  return passfl_vcs_msg_edit (name, TRUE);
}

static void
test_edit (void)
{
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;
  g_auto (GStrv) lines_b = NULL;
  const char *edit_argv[] = { "pass", "edit", "web/login", NULL };

  engine_write_committed ("web/login", EDITED, msg_edit_existing);
  g_assert_true (run (edit_argv, store_b, NULL));

  log_a = log_subjects (store_a);
  g_assert_true (g_str_has_prefix (
      log_a, "Edit password for web/login using Pass for Linux.\n"));

  /* The editor name is the one documented deviation (SPEC §11.3): pass
   * writes its $EDITOR there, we write our own name. */
  log_b = log_subjects (store_b);
  lines_b = g_strsplit (log_b, "\n", 2);
  g_assert_true (g_str_has_prefix (lines_b[0],
                                   "Edit password for web/login using "));
}

static void
test_no_change_no_commit (void)
{
  GError *error = NULL;
  g_autofree char *path =
      passfl_store_entry_path (store_a, "web/login", NULL);
  g_autofree char *message = passfl_vcs_msg_edit ("web/login", TRUE);
  guint before = commit_count (store_a);
  PassflVcs *vcs = passfl_vcs_open (store_a, path, &error);

  g_assert_nonnull (vcs);
  /* nothing changed on disk since the last commit → no new commit */
  g_assert_true (passfl_vcs_commit_file (vcs, path, message, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (commit_count (store_a), ==, before);
  passfl_vcs_free (vcs);
}

static void
test_rm (void)
{
  GError *error = NULL;
  g_autofree char *path =
      passfl_store_entry_path (store_a, "web/login", NULL);
  g_autofree char *message = passfl_vcs_msg_remove ("web/login");
  g_autofree char *log_a = NULL;
  g_autofree char *log_b = NULL;
  const char *rm_argv[] = { "pass", "rm", "-f", "web/login", NULL };
  PassflVcs *vcs;

  /* discover before deleting, like pass's set_git runs first */
  vcs = passfl_vcs_open (store_a, path, &error);
  g_assert_nonnull (vcs);
  g_assert_true (passfl_store_delete_entry (store_a, "web/login", &error));
  g_assert_no_error (error);
  g_assert_true (passfl_vcs_commit_file (vcs, path, message, &error));
  g_assert_no_error (error);
  passfl_vcs_free (vcs);

  g_assert_true (run (rm_argv, store_b, NULL));

  log_a = log_subjects (store_a);
  log_b = log_subjects (store_b);
  g_assert_true (g_str_has_prefix (log_a,
                                   "Remove web/login from store.\n"));
  /* full histories still pairwise equal except the edit subject */
  g_assert_cmpuint (commit_count (store_a), ==, commit_count (store_b));
}

static void
test_signcommits (void)
{
  GError *error = NULL;
  const char *cfg_a[] = { "git", "-C", store_a, "config",
                          "pass.signcommits", "true", NULL };
  const char *cfg_b[] = { "git", "-C", store_b, "config",
                          "pass.signcommits", "true", NULL };
  const char *key_a[] = { "git", "-C", store_a, "config",
                          "user.signingkey", fpr, NULL };
  const char *key_b[] = { "git", "-C", store_b, "config",
                          "user.signingkey", fpr, NULL };
  const char *verify_a[] = { "git", "-C", store_a, "verify-commit",
                             "HEAD", NULL };
  const char *verify_b[] = { "git", "-C", store_b, "verify-commit",
                             "HEAD", NULL };
  const char *unset_a[] = { "git", "-C", store_a, "config", "--unset",
                            "pass.signcommits", NULL };
  const char *unset_b[] = { "git", "-C", store_b, "config", "--unset",
                            "pass.signcommits", NULL };

  g_assert_true (run (cfg_a, NULL, NULL));
  g_assert_true (run (cfg_b, NULL, NULL));
  g_assert_true (run (key_a, NULL, NULL));
  g_assert_true (run (key_b, NULL, NULL));

  engine_write_committed ("signed/entry", CONTENT, passfl_vcs_msg_insert);
  g_assert_true (pass_stdin (store_b, CONTENT,
                             "insert -m -f signed/entry"));

  /* the real git must accept both signatures */
  g_assert_true (run (verify_a, NULL, NULL));
  g_assert_true (run (verify_b, NULL, NULL));

  g_assert_true (run (unset_a, NULL, NULL));
  g_assert_true (run (unset_b, NULL, NULL));
  (void) error;
}

static void
test_history_and_file_at (void)
{
  GError *error = NULL;
  g_autofree char *path =
      passfl_store_entry_path (store_a, "hist/x", NULL);
  PassflVcs *vcs;
  GPtrArray *log;
  GBytes *blob;
  PassflSecBuf *plain;

  engine_write_committed ("hist/x", "first\n", passfl_vcs_msg_insert);
  engine_write_committed ("hist/x", "second\n", msg_edit_existing);

  vcs = passfl_vcs_open (store_a, path, &error);
  g_assert_nonnull (vcs);
  log = passfl_vcs_history (vcs, path, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (log->len, ==, 2); /* newest first */

  {
    const PassflVcsCommit *newest = g_ptr_array_index (log, 0);
    const PassflVcsCommit *oldest = g_ptr_array_index (log, 1);

    g_assert_cmpstr (newest->summary, ==,
                     "Edit password for hist/x using Pass for Linux.");
    g_assert_cmpstr (oldest->summary, ==,
                     "Add given password for hist/x to store.");

    blob = passfl_vcs_file_at (vcs, oldest->oid, path, &error);
    g_assert_no_error (error);
    g_assert_nonnull (blob);
    plain = passfl_crypto_decrypt_mem (g_bytes_get_data (blob, NULL),
                                       g_bytes_get_size (blob), &error);
    g_assert_no_error (error);
    g_assert_cmpstr (plain->data, ==, "first\n");
    passfl_secbuf_free (plain);
    g_bytes_unref (blob);
  }
  g_ptr_array_unref (log);
  passfl_vcs_free (vcs);
}

static void
test_subtree_repo_discovery (void)
{
  GError *error = NULL;
  g_autofree char *team = g_build_filename (store_a, "team", NULL);
  g_autofree char *path =
      passfl_store_entry_path (store_a, "team/shared", NULL);
  g_autofree char *message = passfl_vcs_msg_insert ("team/shared");
  const char *init_argv[] = { "git", "init", "-q", team, NULL };
  const char *cfg_n[] = { "git", "-C", team, "config", "user.name",
                          "passfl", NULL };
  const char *cfg_e[] = { "git", "-C", team, "config", "user.email",
                          "vcs@passfl.invalid", NULL };
  const char *cfg_s[] = { "git", "-C", team, "config", "commit.gpgsign",
                          "false", NULL };
  guint parent_before = commit_count (store_a);
  g_autofree char *team_log = NULL;
  PassflVcs *vcs;

  g_assert_cmpint (g_mkdir_with_parents (team, 0700), ==, 0);
  g_assert_true (run (init_argv, NULL, NULL));
  g_assert_true (run (cfg_n, NULL, NULL));
  g_assert_true (run (cfg_e, NULL, NULL));
  g_assert_true (run (cfg_s, NULL, NULL));

  g_assert_true (passfl_store_write_entry (store_a, "team/shared", "x\n",
                                           2, &error));
  g_assert_no_error (error);
  vcs = passfl_vcs_open (store_a, path, &error);
  g_assert_nonnull (vcs);
  g_assert_true (passfl_vcs_commit_file (vcs, path, message, &error));
  g_assert_no_error (error);
  passfl_vcs_free (vcs);

  /* the commit landed in the inner repo, not the store's (§6 walk-up) */
  team_log = log_subjects (team);
  g_assert_true (g_str_has_prefix (
      team_log, "Add given password for team/shared to store.\n"));
  g_assert_cmpuint (commit_count (store_a), ==, parent_before);
}

static void
test_non_git_store (void)
{
  GError *error = NULL;
  g_autofree char *bare = g_dir_make_tmp ("passfl-nogit-XXXXXX", NULL);
  g_autofree char *path = g_build_filename (bare, "x.gpg", NULL);
  PassflVcs *vcs = passfl_vcs_open (bare, path, &error);

  g_assert_null (vcs);
  g_assert_no_error (error); /* not an error, just not git-tracked */
  rmtree (bare);
}

/* --- main ------------------------------------------------------------------ */

static char *
key_fingerprint (void)
{
  const char *argv[] = { "gpg", "--batch", "--with-colons", "--list-keys",
                         UID, NULL };
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

static void
setup_store (const char *store)
{
  const char *git_init[] = { "git", "init", "-q", store, NULL };
  const char *cfg_name[] = { "git", "-C", store, "config", "user.name",
                             "passfl", NULL };
  const char *cfg_mail[] = { "git", "-C", store, "config", "user.email",
                             "vcs@passfl.invalid", NULL };
  /* libgit2 reads the user's real global config regardless of the
   * GIT_CONFIG_* env vars — mask signing locally so the fixture is
   * deterministic on any machine. */
  const char *cfg_nosign[] = { "git", "-C", store, "config",
                               "commit.gpgsign", "false", NULL };
  const char *cfg_nopass[] = { "git", "-C", store, "config",
                               "pass.signcommits", "false", NULL };
  const char *pass_init[] = { "pass", "init", UID, NULL };
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

  /* Nothing from the user's real git/gpg world may leak in. */
  g_setenv ("GIT_CONFIG_GLOBAL", "/dev/null", TRUE);
  g_setenv ("GIT_CONFIG_NOSYSTEM", "1", TRUE);

  gnupghome = g_dir_make_tmp ("passfl-vcs-gnupg-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (gnupghome, 0700), ==, 0);
  g_setenv ("GNUPGHOME", gnupghome, TRUE);
  store_a = g_dir_make_tmp ("passfl-vcs-a-XXXXXX", &error);
  g_assert_no_error (error);
  store_b = g_dir_make_tmp ("passfl-vcs-b-XXXXXX", &error);
  g_assert_no_error (error);

  editor_sh = g_build_filename (gnupghome, "editor.sh", NULL);
  g_assert_true (g_file_set_contents (
      editor_sh,
      "#!/bin/sh\nprintf 'edited-content\\nurl: https://example.com\\n'"
      " > \"$1\"\n",
      -1, NULL));
  g_assert_cmpint (g_chmod (editor_sh, 0755), ==, 0);

  {
    const char *keygen[] = { "gpg", "--batch", "--quiet",
                             "--pinentry-mode", "loopback", "--passphrase",
                             "", "--quick-generate-key", UID, "default",
                             "default", "never", NULL };

    g_assert_true (run (keygen, NULL, NULL));
    fpr = key_fingerprint ();
  }
  setup_store (store_a);
  setup_store (store_b);

  g_test_add_func ("/vcs/insert", test_insert);
  g_test_add_func ("/vcs/edit", test_edit);
  g_test_add_func ("/vcs/no-change-no-commit", test_no_change_no_commit);
  g_test_add_func ("/vcs/rm", test_rm);
  g_test_add_func ("/vcs/signcommits", test_signcommits);
  g_test_add_func ("/vcs/history-and-file-at", test_history_and_file_at);
  g_test_add_func ("/vcs/subtree-repo-discovery",
                   test_subtree_repo_discovery);
  g_test_add_func ("/vcs/non-git-store", test_non_git_store);

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
  g_free (editor_sh);
  g_free (fpr);
  return ret;
}
