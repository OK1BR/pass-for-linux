/* generate_test.c — M2 gate (pass-generate-test): tr-set expansion and
 * rejection-sampled generation (SPEC §4.8).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "generate.h"

#include <gcrypt.h>
#include <string.h>

static void
test_expand_classes (void)
{
  GError *error = NULL;
  g_autofree char *digit = passfl_generate_expand_set ("[:digit:]", &error);
  g_autofree char *alnum = passfl_generate_expand_set ("[:alnum:]", NULL);
  g_autofree char *punct = passfl_generate_expand_set ("[:punct:]", NULL);
  g_autofree char *both =
      passfl_generate_expand_set ("[:punct:][:alnum:]", NULL);

  g_assert_no_error (error);
  g_assert_cmpstr (digit, ==, "0123456789");
  g_assert_cmpuint (strlen (alnum), ==, 62);
  g_assert_cmpuint (strlen (punct), ==, 32); /* ASCII punctuation, C locale */
  g_assert_cmpuint (strlen (both), ==, 94);
}

static void
test_expand_literals_and_ranges (void)
{
  g_autofree char *lit = passfl_generate_expand_set ("abc#@", NULL);
  g_autofree char *range = passfl_generate_expand_set ("a-f0-2", NULL);
  g_autofree char *dedup = passfl_generate_expand_set ("aab-c", NULL);
  g_autofree char *dash = passfl_generate_expand_set ("a-", NULL);

  g_assert_cmpstr (lit, ==, "abc#@");
  g_assert_cmpstr (range, ==, "abcdef012");
  g_assert_cmpstr (dedup, ==, "abc");
  g_assert_cmpstr (dash, ==, "a-"); /* trailing '-' stays literal */
}

static void
test_expand_errors (void)
{
  GError *error = NULL;

  g_assert_null (passfl_generate_expand_set ("[:bogus:]", &error));
  g_assert_error (error, PASSFL_GENERATE_ERROR, PASSFL_GENERATE_ERROR_SET);
  g_clear_error (&error);

  g_assert_null (passfl_generate_expand_set ("", &error));
  g_assert_error (error, PASSFL_GENERATE_ERROR, PASSFL_GENERATE_ERROR_SET);
  g_clear_error (&error);
}

static void
test_password_defaults (void)
{
  GError *error = NULL;
  g_autofree char *alphabet =
      passfl_generate_expand_set ("[:punct:][:alnum:]", NULL);
  PassflSecBuf *buf = passfl_generate_password (0, FALSE, &error);

  g_assert_no_error (error);
  g_assert_cmpuint (buf->len, ==, 25); /* §4.8 default */
  for (gsize i = 0; i < buf->len; i++)
    g_assert_nonnull (strchr (alphabet, buf->data[i]));
  g_assert_true (gcry_is_secure (buf->data));
  passfl_secbuf_free (buf);
}

static void
test_password_env_and_no_symbols (void)
{
  GError *error = NULL;
  PassflSecBuf *buf;

  g_setenv ("PASSWORD_STORE_GENERATED_LENGTH", "40", TRUE);
  buf = passfl_generate_password (0, TRUE, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (buf->len, ==, 40);
  for (gsize i = 0; i < buf->len; i++)
    g_assert_true (g_ascii_isalnum (buf->data[i])); /* no symbols */
  passfl_secbuf_free (buf);
  g_unsetenv ("PASSWORD_STORE_GENERATED_LENGTH");

  g_setenv ("PASSWORD_STORE_CHARACTER_SET", "abc", TRUE);
  buf = passfl_generate_password (100, FALSE, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (buf->len, ==, 100);
  for (gsize i = 0; i < buf->len; i++)
    g_assert_true (buf->data[i] >= 'a' && buf->data[i] <= 'c');
  passfl_secbuf_free (buf);
  g_unsetenv ("PASSWORD_STORE_CHARACTER_SET");
}

int
main (int argc, char **argv)
{
  GError *error = NULL;

  g_test_init (&argc, &argv, NULL);
  g_assert_true (passfl_crypto_init (&error));
  g_assert_no_error (error);

  g_test_add_func ("/generate/expand-classes", test_expand_classes);
  g_test_add_func ("/generate/expand-literals-ranges",
                   test_expand_literals_and_ranges);
  g_test_add_func ("/generate/expand-errors", test_expand_errors);
  g_test_add_func ("/generate/password-defaults", test_password_defaults);
  g_test_add_func ("/generate/password-env", test_password_env_and_no_symbols);

  return g_test_run ();
}
