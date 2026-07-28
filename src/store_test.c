/* store_test.c — M0 gate (pass-store-test): tree scan of a fixture store.
 *
 * Builds a throwaway store in a temp directory — the user's real
 * ~/.password-store is never touched (CLAUDE.md rule 4).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "store.h"

#include <ftw.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char *fixture; /* store root, created in main() */

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

static void
put_file (const char *rel, const char *content)
{
  g_autofree char *path = g_build_filename (fixture, rel, NULL);
  g_autofree char *dir = g_path_get_dirname (path);

  g_assert_cmpint (g_mkdir_with_parents (dir, 0700), ==, 0);
  g_assert_true (g_file_set_contents (path, content, -1, NULL));
}

/* Fixture:
 *   bank.gpg                  entry at the root
 *   empty/                    directory with no entries
 *   link.gpg -> bank.gpg      symlinked entry (read-only per SPEC §2.1)
 *   loop/up -> ..             symlink cycle — scan must terminate
 *   social/{github,mastodon}.gpg
 *   work/dev/aws.gpg          nested entry
 *   README                    stray non-.gpg file, not an entry
 *   .gpg-id .git/ .extensions/ .gitattributes   hidden format internals
 */
static void
build_fixture (void)
{
  g_autofree char *link_path = g_build_filename (fixture, "link.gpg", NULL);
  g_autofree char *loop_dir = g_build_filename (fixture, "loop", NULL);
  g_autofree char *loop_link = g_build_filename (fixture, "loop", "up", NULL);
  g_autofree char *empty_dir = g_build_filename (fixture, "empty", NULL);

  put_file ("bank.gpg", "x");
  put_file ("social/github.gpg", "x");
  put_file ("social/mastodon.gpg", "x");
  put_file ("work/dev/aws.gpg", "x");
  put_file ("README", "not an entry");
  put_file (".gpg-id", "AAAA1234");
  put_file (".git/config", "");
  put_file (".extensions/foo.bash", "");
  put_file (".gitattributes", "*.gpg diff=gpg");
  g_assert_cmpint (g_mkdir_with_parents (empty_dir, 0700), ==, 0);
  g_assert_cmpint (g_mkdir_with_parents (loop_dir, 0700), ==, 0);
  g_assert_cmpint (symlink ("bank.gpg", link_path), ==, 0);
  g_assert_cmpint (symlink ("..", loop_link), ==, 0);
}

static const PassflNode *
child (const PassflNode *node, guint i)
{
  g_assert_cmpuint (i, <, node->children->len);
  return g_ptr_array_index (node->children, i);
}

static void
test_scan_tree (void)
{
  GError *error = NULL;
  PassflNode *root = passfl_store_scan (fixture, &error);
  const PassflNode *n;

  g_assert_no_error (error);
  g_assert_nonnull (root);
  g_assert_cmpint (root->kind, ==, PASSFL_NODE_DIR);
  g_assert_cmpstr (root->rel, ==, "");

  /* Sorted: bank, empty/, link, loop/, social/, work/ — dotfiles and
   * README invisible. */
  g_assert_cmpuint (root->children->len, ==, 6);

  n = child (root, 0);
  g_assert_cmpint (n->kind, ==, PASSFL_NODE_ENTRY);
  g_assert_cmpstr (n->name, ==, "bank");
  g_assert_cmpstr (n->rel, ==, "bank");
  g_assert_false (n->is_symlink);

  n = child (root, 1);
  g_assert_cmpint (n->kind, ==, PASSFL_NODE_DIR);
  g_assert_cmpstr (n->name, ==, "empty");
  g_assert_cmpuint (n->children->len, ==, 0);

  n = child (root, 2);
  g_assert_cmpint (n->kind, ==, PASSFL_NODE_ENTRY);
  g_assert_cmpstr (n->name, ==, "link");
  g_assert_true (n->is_symlink);

  /* loop/up points back at the root: shown as a directory, but the cycle
   * is cut — it has no children of its own. */
  n = child (root, 3);
  g_assert_cmpstr (n->name, ==, "loop");
  g_assert_cmpuint (n->children->len, ==, 1);
  n = child (n, 0);
  g_assert_cmpint (n->kind, ==, PASSFL_NODE_DIR);
  g_assert_cmpstr (n->name, ==, "up");
  g_assert_true (n->is_symlink);
  g_assert_cmpuint (n->children->len, ==, 0);

  n = child (root, 4);
  g_assert_cmpstr (n->name, ==, "social");
  g_assert_cmpuint (n->children->len, ==, 2);
  g_assert_cmpstr (child (n, 0)->rel, ==, "social/github");
  g_assert_cmpstr (child (n, 1)->rel, ==, "social/mastodon");

  n = child (root, 5);
  g_assert_cmpstr (n->name, ==, "work");
  n = child (n, 0);
  g_assert_cmpstr (n->name, ==, "dev");
  g_assert_cmpstr (child (n, 0)->rel, ==, "work/dev/aws");

  passfl_node_free (root);
}

static void
test_list_entries (void)
{
  GError *error = NULL;
  GPtrArray *entries = passfl_store_list_entries (fixture, &error);
  const char *expected[] = {
    "bank", "link", "social/github", "social/mastodon", "work/dev/aws",
  };

  g_assert_no_error (error);
  g_assert_nonnull (entries);
  g_assert_cmpuint (entries->len, ==, G_N_ELEMENTS (expected));
  for (guint i = 0; i < entries->len; i++)
    g_assert_cmpstr (g_ptr_array_index (entries, i), ==, expected[i]);
  g_ptr_array_unref (entries);
}

static void
test_scan_missing (void)
{
  GError *error = NULL;
  g_autofree char *bogus = g_build_filename (fixture, "no-such-dir", NULL);

  g_assert_null (passfl_store_scan (bogus, &error));
  g_assert_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_SCAN);
  g_error_free (error);
}

static void
test_default_dir (void)
{
  g_autofree char *from_env = NULL;
  g_autofree char *fallback = NULL;
  g_autofree char *empty_env = NULL;

  g_setenv ("PASSWORD_STORE_DIR", "/tmp/some-store", TRUE);
  from_env = passfl_store_default_dir ();
  g_assert_cmpstr (from_env, ==, "/tmp/some-store");

  /* Empty counts as unset, like ${PASSWORD_STORE_DIR:-…}. */
  g_setenv ("PASSWORD_STORE_DIR", "", TRUE);
  empty_env = passfl_store_default_dir ();
  g_assert_true (g_str_has_suffix (empty_env, "/.password-store"));

  g_unsetenv ("PASSWORD_STORE_DIR");
  fallback = passfl_store_default_dir ();
  g_assert_true (g_str_has_suffix (fallback, "/.password-store"));
}

static void
test_name_safety (void)
{
  static const char *safe[] = {
    "bank", "social/github", "a..b", "..a", "a..", "...", ".hidden", "",
  };
  static const char *sneaky[] = {
    "..", "../bank", "social/..", "social/../bank", "../../etc/shadow",
  };

  for (guint i = 0; i < G_N_ELEMENTS (safe); i++)
    g_assert_true (passfl_entry_name_is_safe (safe[i]));
  for (guint i = 0; i < G_N_ELEMENTS (sneaky); i++)
    g_assert_false (passfl_entry_name_is_safe (sneaky[i]));
}

int
main (int argc, char **argv)
{
  int ret;
  GError *error = NULL;

  g_test_init (&argc, &argv, NULL);

  fixture = g_dir_make_tmp ("passfl-store-XXXXXX", &error);
  g_assert_no_error (error);
  build_fixture ();

  g_test_add_func ("/store/scan-tree", test_scan_tree);
  g_test_add_func ("/store/list-entries", test_list_entries);
  g_test_add_func ("/store/scan-missing", test_scan_missing);
  g_test_add_func ("/store/default-dir", test_default_dir);
  g_test_add_func ("/store/name-safety", test_name_safety);

  ret = g_test_run ();
  rmtree (fixture);
  g_free (fixture);
  return ret;
}
