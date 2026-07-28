/* recipients_test.c — M0 gate (pass-recipients-test): .gpg-id resolution
 * against fixture stores (SPEC §2.2), never the user's real one.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "recipients.h"

#include <ftw.h>
#include <glib/gstdio.h>
#include <stdio.h>

static char *fixture; /* initialised store */
static char *bare;    /* store with no .gpg-id anywhere */

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
put_file (const char *root, const char *rel, const char *content)
{
  g_autofree char *path = g_build_filename (root, rel, NULL);
  g_autofree char *dir = g_path_get_dirname (path);

  g_assert_cmpint (g_mkdir_with_parents (dir, 0700), ==, 0);
  g_assert_true (g_file_set_contents (path, content, -1, NULL));
}

/* Fixture:
 *   .gpg-id                AAAA + BBBB + richard@example.org (with comments)
 *   social/.gpg-id         CCCC — overrides the root for that subtree
 *   social/deep/           no own .gpg-id → walks up to social/
 *   work/                  no own .gpg-id → walks up to the root
 *   empty-id/.gpg-id       only comments/blanks → zero recipients
 */
static void
build_fixture (void)
{
  put_file (fixture, ".gpg-id",
            "AAAA\n"
            "# a full-line comment\n"
            "BBBB # a trailing comment\n"
            "\n"
            "   \n"
            "richard@example.org\n");
  put_file (fixture, "social/.gpg-id", "CCCC\n");
  put_file (fixture, "social/deep/x.gpg", "x");
  put_file (fixture, "work/x.gpg", "x");
  put_file (fixture, "empty-id/.gpg-id", "# nothing but this comment\n\n");
}

static void
test_parse (void)
{
  g_auto (GStrv) ids =
      passfl_gpg_id_parse ("  0xAB12  \n#c\nFull Name <a@b.cz> # c\n\nX\n");

  g_assert_cmpuint (g_strv_length (ids), ==, 3);
  g_assert_cmpstr (ids[0], ==, "0xAB12");
  g_assert_cmpstr (ids[1], ==, "Full Name <a@b.cz>");
  g_assert_cmpstr (ids[2], ==, "X");
}

static void
test_root (void)
{
  GError *error = NULL;
  g_autofree char *gpg_id_file = NULL;
  g_autofree char *expected = g_build_filename (fixture, ".gpg-id", NULL);
  g_auto (GStrv) ids =
      passfl_recipients_resolve (fixture, "", &gpg_id_file, &error);

  g_assert_no_error (error);
  g_assert_cmpuint (g_strv_length (ids), ==, 3);
  g_assert_cmpstr (ids[0], ==, "AAAA");
  g_assert_cmpstr (ids[1], ==, "BBBB");
  g_assert_cmpstr (ids[2], ==, "richard@example.org");
  g_assert_cmpstr (gpg_id_file, ==, expected);
}

static void
test_nested_override (void)
{
  GError *error = NULL;
  g_autofree char *gpg_id_file = NULL;
  g_autofree char *expected =
      g_build_filename (fixture, "social", ".gpg-id", NULL);
  g_auto (GStrv) ids =
      passfl_recipients_resolve (fixture, "social", &gpg_id_file, &error);

  g_assert_no_error (error);
  /* Full override, no merge with the root's list (SPEC §2.2). */
  g_assert_cmpuint (g_strv_length (ids), ==, 1);
  g_assert_cmpstr (ids[0], ==, "CCCC");
  g_assert_cmpstr (gpg_id_file, ==, expected);
}

static void
test_walk_up (void)
{
  GError *error = NULL;
  g_auto (GStrv) deep =
      passfl_recipients_resolve (fixture, "social/deep", NULL, &error);
  g_auto (GStrv) work = NULL;
  g_auto (GStrv) unborn = NULL;

  g_assert_no_error (error);
  g_assert_cmpuint (g_strv_length (deep), ==, 1);
  g_assert_cmpstr (deep[0], ==, "CCCC");

  work = passfl_recipients_resolve (fixture, "work", NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_strv_length (work), ==, 3);
  g_assert_cmpstr (work[0], ==, "AAAA");

  /* A directory that does not exist yet resolves too — the walk only
   * tests for .gpg-id files, exactly like pass (lines 82–86). */
  unborn = passfl_recipients_resolve (fixture, "social/deep/newdir", NULL,
                                      &error);
  g_assert_no_error (error);
  g_assert_cmpstr (unborn[0], ==, "CCCC");
}

static void
test_env_key_override (void)
{
  GError *error = NULL;
  g_autofree char *gpg_id_file = NULL;
  g_auto (GStrv) ids = NULL;
  g_auto (GStrv) in_bare = NULL;

  g_setenv ("PASSWORD_STORE_KEY", "XXXX  \tYYYY", TRUE);

  ids = passfl_recipients_resolve (fixture, "social", &gpg_id_file, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_strv_length (ids), ==, 2);
  g_assert_cmpstr (ids[0], ==, "XXXX");
  g_assert_cmpstr (ids[1], ==, "YYYY");
  g_assert_null (gpg_id_file); /* no file was consulted at all */

  /* …not even in a store that has no .gpg-id whatsoever. */
  in_bare = passfl_recipients_resolve (bare, "", NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_strv_length (in_bare), ==, 2);

  g_unsetenv ("PASSWORD_STORE_KEY");
}

static void
test_uninitialised (void)
{
  GError *error = NULL;

  g_assert_null (passfl_recipients_resolve (bare, "", NULL, &error));
  g_assert_error (error, PASSFL_RECIPIENTS_ERROR,
                  PASSFL_RECIPIENTS_ERROR_UNINITIALIZED);
  g_clear_error (&error);

  g_assert_null (passfl_recipients_resolve (bare, "some/sub", NULL, &error));
  g_assert_error (error, PASSFL_RECIPIENTS_ERROR,
                  PASSFL_RECIPIENTS_ERROR_UNINITIALIZED);
  g_clear_error (&error);
}

static void
test_empty_gpg_id (void)
{
  GError *error = NULL;
  g_auto (GStrv) ids =
      passfl_recipients_resolve (fixture, "empty-id", NULL, &error);

  /* The file exists, so the walk stops there — zero recipients, no error,
   * same as pass. */
  g_assert_no_error (error);
  g_assert_nonnull (ids);
  g_assert_cmpuint (g_strv_length (ids), ==, 0);
}

static void
test_sneaky_path (void)
{
  GError *error = NULL;

  g_assert_null (passfl_recipients_resolve (fixture, "../etc", NULL, &error));
  g_assert_error (error, PASSFL_RECIPIENTS_ERROR,
                  PASSFL_RECIPIENTS_ERROR_SNEAKY_PATH);
  g_clear_error (&error);
}

int
main (int argc, char **argv)
{
  int ret;
  GError *error = NULL;

  g_test_init (&argc, &argv, NULL);

  /* The environment decides resolution (§2.2) — start from a known state. */
  g_unsetenv ("PASSWORD_STORE_KEY");

  fixture = g_dir_make_tmp ("passfl-recips-XXXXXX", &error);
  g_assert_no_error (error);
  bare = g_dir_make_tmp ("passfl-bare-XXXXXX", &error);
  g_assert_no_error (error);
  build_fixture ();

  g_test_add_func ("/recipients/parse", test_parse);
  g_test_add_func ("/recipients/root", test_root);
  g_test_add_func ("/recipients/nested-override", test_nested_override);
  g_test_add_func ("/recipients/walk-up", test_walk_up);
  g_test_add_func ("/recipients/env-key-override", test_env_key_override);
  g_test_add_func ("/recipients/uninitialised", test_uninitialised);
  g_test_add_func ("/recipients/empty-gpg-id", test_empty_gpg_id);
  g_test_add_func ("/recipients/sneaky-path", test_sneaky_path);

  ret = g_test_run ();
  rmtree (fixture);
  rmtree (bare);
  g_free (fixture);
  g_free (bare);
  return ret;
}
