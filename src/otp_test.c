/* otp_test.c — M5 gate (pass-otp-test): RFC 4226/6238 vectors, the URI
 * parse matrix, and conformance against the real `pass otp`.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "crypto.h"
#include "otp.h"
#include "store.h"

#include <ftw.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#define UID "passfl-otp <otp@passfl.invalid>"
/* base32 of the RFC 6238 reference secrets */
#define B32_SHA1 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
#define B32_SHA256 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
#define B32_SHA512                                                        \
  "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZD" \
  "GNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="

static char *gnupghome;
static char *store;

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
run (const char *const *argv, char **out)
{
  g_auto (GStrv) env = g_get_environ ();
  gint status = -1;
  g_autofree char *err = NULL;
  char *stdout_buf = NULL;
  gboolean ok;

  env = g_environ_setenv (env, "PASSWORD_STORE_DIR", store, TRUE);
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

/* --- parse ------------------------------------------------------------------ */

static void
test_parse (void)
{
  GError *error = NULL;
  PassflOtp *otp;

  otp = passfl_otp_parse (
      "otpauth://totp/GitHub:OK1BR?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
      "&digits=8&period=60&algorithm=SHA256",
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (passfl_otp_type (otp), ==, PASSFL_OTP_TOTP);
  g_assert_cmpstr (passfl_otp_display (otp), ==, "OK1BR");
  g_assert_cmpuint (passfl_otp_period (otp), ==, 60);
  passfl_otp_free (otp);

  /* defaults when parameters are absent */
  otp = passfl_otp_parse ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
                          &error);
  g_assert_no_error (error);
  g_assert_cmpuint (passfl_otp_period (otp), ==, 30);
  passfl_otp_free (otp);

  /* url-encoded account survives */
  otp = passfl_otp_parse (
      "otpauth://totp/My%20Site:me%40example.com?secret=JBSWY3DPEHPK3PXP",
      &error);
  g_assert_no_error (error);
  g_assert_cmpstr (passfl_otp_display (otp), ==, "me@example.com");
  passfl_otp_free (otp);

  /* hotp with counter */
  otp = passfl_otp_parse (
      "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=41", &error);
  g_assert_no_error (error);
  g_assert_cmpint (passfl_otp_type (otp), ==, PASSFL_OTP_HOTP);
  g_assert_cmpuint (passfl_otp_counter (otp), ==, 41);
  passfl_otp_free (otp);
}

static void
test_parse_errors (void)
{
  GError *error = NULL;

  /* missing secret */
  g_assert_null (passfl_otp_parse ("otpauth://totp/x?digits=6", &error));
  g_assert_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_URI);
  g_clear_error (&error);

  /* missing account name */
  g_assert_null (
      passfl_otp_parse ("otpauth://totp?secret=JBSWY3DPEHPK3PXP", &error));
  g_assert_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_URI);
  g_clear_error (&error);

  /* hotp without counter */
  g_assert_null (
      passfl_otp_parse ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
                        &error));
  g_assert_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_URI);
  g_clear_error (&error);

  /* not an otpauth URI at all */
  g_assert_null (passfl_otp_parse ("https://example.com", &error));
  g_clear_error (&error);
}

/* --- RFC vectors ------------------------------------------------------------ */

static void
assert_totp (const char *b32, const char *algo, gint64 t,
             const char *expected)
{
  GError *error = NULL;
  g_autofree char *uri = g_strdup_printf (
      "otpauth://totp/rfc?secret=%s&digits=8%s%s", b32,
      algo != NULL ? "&algorithm=" : "", algo != NULL ? algo : "");
  PassflOtp *otp = passfl_otp_parse (uri, &error);
  g_autofree char *code = NULL;

  g_assert_no_error (error);
  code = passfl_otp_code (otp, t, &error);
  g_assert_no_error (error);
  g_assert_cmpstr (code, ==, expected);
  passfl_otp_free (otp);
}

static void
test_rfc6238_vectors (void)
{
  /* RFC 6238, Appendix B */
  assert_totp (B32_SHA1, NULL, 59, "94287082");
  assert_totp (B32_SHA1, NULL, 1111111109, "07081804");
  assert_totp (B32_SHA1, NULL, 1111111111, "14050471");
  assert_totp (B32_SHA1, NULL, 1234567890, "89005924");
  assert_totp (B32_SHA1, NULL, 2000000000, "69279037");
  assert_totp (B32_SHA1, NULL, 20000000000, "65353130");
  assert_totp (B32_SHA256, "SHA256", 59, "46119246");
  assert_totp (B32_SHA256, "SHA256", 1111111109, "68084774");
  assert_totp (B32_SHA256, "SHA256", 2000000000, "90698825");
  assert_totp (B32_SHA512, "SHA512", 59, "90693936");
  assert_totp (B32_SHA512, "SHA512", 1234567890, "93441116");
  assert_totp (B32_SHA512, "SHA512", 20000000000, "47863826");
}

static void
test_rfc4226_vectors (void)
{
  /* RFC 4226, Appendix D — 6-digit HOTP for counters 0…9 */
  static const char *expected[] = {
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
  };
  GError *error = NULL;
  g_autofree char *uri = g_strdup_printf (
      "otpauth://hotp/rfc?secret=%s&counter=0", B32_SHA1);
  PassflOtp *otp = passfl_otp_parse (uri, &error);

  g_assert_no_error (error);
  for (guint64 c = 0; c < G_N_ELEMENTS (expected); c++)
    {
      g_autofree char *code = passfl_otp_hotp_code (otp, c, &error);

      g_assert_no_error (error);
      g_assert_cmpstr (code, ==, expected[c]);
    }
  passfl_otp_free (otp);
}

static void
test_remaining_and_increment (void)
{
  GError *error = NULL;
  PassflOtp *totp = passfl_otp_parse (
      "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", &error);
  PassflOtp *hotp = passfl_otp_parse (
      "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&issuer=I&counter=41",
      &error);
  g_autofree char *bumped = NULL;

  g_assert_no_error (error);
  g_assert_cmpuint (passfl_otp_remaining (totp, 59), ==, 1);
  g_assert_cmpuint (passfl_otp_remaining (totp, 60), ==, 30);

  bumped = passfl_otp_incremented_uri (hotp);
  g_assert_cmpstr (
      bumped, ==,
      "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&issuer=I&counter=42");

  passfl_otp_free (totp);
  passfl_otp_free (hotp);
}

/* --- conformance vs pass otp ------------------------------------------------ */

static void
test_pass_otp_conformance (void)
{
  GError *error = NULL;
  g_autofree char *uri = g_strdup_printf (
      "otpauth://totp/conf?secret=%s&digits=8&algorithm=SHA256&period=60",
      B32_SHA256);
  g_autofree char *content = g_strdup_printf ("pw\n%s\n", uri);
  const char *otp_argv[] = { "pass", "otp", "conf", NULL };
  g_autofree char *out = NULL;
  PassflOtp *otp;
  g_autofree char *ours = NULL;
  gint64 now;

  g_assert_true (passfl_store_write_entry (store, "conf", content,
                                           strlen (content), &error));
  g_assert_no_error (error);

  otp = passfl_otp_parse (uri, &error);
  g_assert_no_error (error);
  /* stay clear of a period boundary so both sides sample the same slot */
  now = (gint64) (g_get_real_time () / G_USEC_PER_SEC);
  if (passfl_otp_remaining (otp, now) < 5)
    {
      g_usleep ((gulong) passfl_otp_remaining (otp, now) * G_USEC_PER_SEC);
      now = (gint64) (g_get_real_time () / G_USEC_PER_SEC);
    }

  g_assert_true (run (otp_argv, &out));
  g_strstrip (out);
  ours = passfl_otp_code (otp, now, &error);
  g_assert_no_error (error);
  g_assert_cmpstr (ours, ==, out);
  passfl_otp_free (otp);
}

static void
test_pass_otp_hotp_interop (void)
{
  GError *error = NULL;
  g_autofree char *uri = g_strdup_printf (
      "otpauth://hotp/conf?secret=%s&counter=3", B32_SHA1);
  g_autofree char *content = g_strdup_printf ("pw\n%s\n", uri);
  const char *otp_argv[] = { "pass", "otp", "hotpe", NULL };
  g_autofree char *out = NULL;
  g_autofree char *path = NULL;
  PassflOtp *otp;
  PassflSecBuf *plain;
  g_autofree char *ours = NULL;

  g_assert_true (passfl_store_write_entry (store, "hotpe", content,
                                           strlen (content), &error));
  g_assert_no_error (error);

  /* pass otp generates at counter+1 = 4 and rewrites the entry */
  g_assert_true (run (otp_argv, &out));
  g_strstrip (out);

  otp = passfl_otp_parse (uri, &error);
  g_assert_no_error (error);
  ours = passfl_otp_hotp_code (otp, 4, &error);
  g_assert_no_error (error);
  g_assert_cmpstr (ours, ==, out);
  passfl_otp_free (otp);

  /* and the rewritten entry now carries counter=4, parseable by us */
  path = passfl_store_entry_path (store, "hotpe", NULL);
  plain = passfl_crypto_decrypt_file (path, &error);
  g_assert_no_error (error);
  g_assert_nonnull (strstr (plain->data, "counter=4"));
  passfl_secbuf_free (plain);
}

/* --- main ------------------------------------------------------------------ */

int
main (int argc, char **argv)
{
  int ret;
  GError *error = NULL;
  g_autofree char *gpg = g_find_program_in_path ("gpg");
  g_autofree char *pass = g_find_program_in_path ("pass");
  g_autofree char *oath = g_find_program_in_path ("oathtool");
  gboolean with_pass;

  g_test_init (&argc, &argv, NULL);
  g_assert_true (passfl_crypto_init (&error));
  g_assert_no_error (error);

  g_test_add_func ("/otp/parse", test_parse);
  g_test_add_func ("/otp/parse-errors", test_parse_errors);
  g_test_add_func ("/otp/rfc6238-vectors", test_rfc6238_vectors);
  g_test_add_func ("/otp/rfc4226-vectors", test_rfc4226_vectors);
  g_test_add_func ("/otp/remaining-and-increment",
                   test_remaining_and_increment);

  with_pass = gpg != NULL && pass != NULL && oath != NULL;
  if (with_pass)
    {
      gnupghome = g_dir_make_tmp ("passfl-otp-gnupg-XXXXXX", &error);
      g_assert_no_error (error);
      g_assert_cmpint (g_chmod (gnupghome, 0700), ==, 0);
      g_setenv ("GNUPGHOME", gnupghome, TRUE);
      store = g_dir_make_tmp ("passfl-otp-store-XXXXXX", &error);
      g_assert_no_error (error);

      {
        const char *keygen[] = { "gpg", "--batch", "--quiet",
                                 "--pinentry-mode", "loopback",
                                 "--passphrase", "",
                                 "--quick-generate-key", UID, "default",
                                 "default", "never", NULL };
        const char *pass_init[] = { "pass", "init", UID, NULL };

        g_assert_true (run (keygen, NULL));
        g_assert_true (run (pass_init, NULL));
      }
      g_test_add_func ("/otp/pass-otp-conformance",
                       test_pass_otp_conformance);
      g_test_add_func ("/otp/pass-otp-hotp-interop",
                       test_pass_otp_hotp_interop);
    }

  ret = g_test_run ();

  if (with_pass)
    {
      const char *kill_agent[] = { "gpgconf", "--kill", "gpg-agent",
                                   NULL };

      run (kill_agent, NULL);
      rmtree (gnupghome);
      rmtree (store);
      g_free (gnupghome);
      g_free (store);
    }
  return ret;
}
