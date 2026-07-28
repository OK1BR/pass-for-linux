/* entry_test.c — M1 gate (pass-entry-test): content parsing, kv hints,
 * secure-memory placement.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"
#include "entry.h"

#include <gcrypt.h>
#include <string.h>

static void
test_parse_typical (void)
{
  const char *content =
      "hunter2\n"
      "url: https://example.com\n"
      "user: rfa\n"
      "\n"
      "free text note\n"
      "otpauth://totp/x?secret=ABC\n";
  PassflEntry *e = passfl_entry_parse (content, strlen (content));

  g_assert_cmpuint (passfl_entry_n_lines (e), ==, 6);
  g_assert_cmpstr (passfl_entry_password (e), ==, "hunter2");
  g_assert_cmpstr (passfl_entry_line (e, 1), ==, "url: https://example.com");
  g_assert_cmpstr (passfl_entry_line (e, 3), ==, ""); /* interior blank */
  g_assert_cmpstr (passfl_entry_line (e, 4), ==, "free text note");
  g_assert_true (passfl_entry_final_newline (e));
  passfl_entry_free (e);
}

static void
test_parse_edges (void)
{
  PassflEntry *empty = passfl_entry_parse ("", 0);
  PassflEntry *no_nl = passfl_entry_parse ("onlypass", 8);

  g_assert_cmpuint (passfl_entry_n_lines (empty), ==, 0);
  g_assert_cmpstr (passfl_entry_password (empty), ==, "");
  g_assert_false (passfl_entry_final_newline (empty));

  g_assert_cmpuint (passfl_entry_n_lines (no_nl), ==, 1);
  g_assert_cmpstr (passfl_entry_password (no_nl), ==, "onlypass");
  g_assert_false (passfl_entry_final_newline (no_nl));

  passfl_entry_free (empty);
  passfl_entry_free (no_nl);
}

static void
test_secure_memory (void)
{
  const char *content = "secret\nuser: x\n";
  PassflEntry *e = passfl_entry_parse (content, strlen (content));
  PassflSecBuf *buf = passfl_secbuf_new ("abc", -1);

  /* Everything parsed or copied must sit in the mlocked pool (SPEC §7.2). */
  g_assert_true (gcry_is_secure (passfl_entry_password (e)));
  g_assert_true (gcry_is_secure (passfl_entry_line (e, 1)));
  g_assert_true (gcry_is_secure (buf->data));
  g_assert_cmpstr (buf->data, ==, "abc");
  g_assert_cmpuint (buf->len, ==, 3);

  passfl_secbuf_free (buf);
  passfl_entry_free (e);
}

static void
test_kv (void)
{
  gsize key_len;
  const char *value;

  g_assert_true (passfl_entry_line_kv ("url: https://ex.com", &key_len,
                                       &value));
  g_assert_cmpuint (key_len, ==, 3);
  g_assert_cmpstr (value, ==, "https://ex.com");

  g_assert_true (passfl_entry_line_kv ("user:rfa", &key_len, &value));
  g_assert_cmpstr (value, ==, "rfa");

  g_assert_true (passfl_entry_line_kv ("Recovery codes: a b c", &key_len,
                                       &value));
  g_assert_cmpuint (key_len, ==, 14);

  g_assert_true (passfl_entry_line_kv ("empty:", &key_len, &value));
  g_assert_cmpstr (value, ==, "");

  /* Not key/value: no colon, empty key, URI-shaped lines. */
  g_assert_false (passfl_entry_line_kv ("free text", NULL, NULL));
  g_assert_false (passfl_entry_line_kv (": nokey", NULL, NULL));
  g_assert_false (passfl_entry_line_kv ("https://example.com", NULL, NULL));
  g_assert_false (passfl_entry_line_kv ("otpauth://totp/x", NULL, NULL));
}

static void
test_otp (void)
{
  g_assert_true (passfl_entry_line_is_otp ("otpauth://totp/x?secret=A"));
  g_assert_true (passfl_entry_line_is_otp ("otpauth://hotp/x?secret=A"));
  g_assert_false (passfl_entry_line_is_otp ("otpauth://other/x"));
  g_assert_false (passfl_entry_line_is_otp ("url: otpauth"));
}

int
main (int argc, char **argv)
{
  GError *error = NULL;

  g_test_init (&argc, &argv, NULL);

  /* Secure memory must be up before any parse. */
  g_assert_true (passfl_crypto_init (&error));
  g_assert_no_error (error);

  g_test_add_func ("/entry/parse-typical", test_parse_typical);
  g_test_add_func ("/entry/parse-edges", test_parse_edges);
  g_test_add_func ("/entry/secure-memory", test_secure_memory);
  g_test_add_func ("/entry/kv", test_kv);
  g_test_add_func ("/entry/otp", test_otp);

  return g_test_run ();
}
