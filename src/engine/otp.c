/* otp.c — otpauth:// parsing and HMAC codes, M5 (docs/SPEC.md §2.3).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "otp.h"

#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

G_DEFINE_QUARK (passfl-otp-error, passfl_otp_error)

struct _PassflOtp {
  PassflOtpType type;
  char *uri;            /* the original line, verbatim */
  char *issuer;         /* urldecoded; may be NULL */
  char *account;        /* urldecoded; never NULL after parse */
  PassflSecBuf *secret; /* base32 string as given */
  char *algorithm;      /* raw param or NULL */
  char *digits;         /* raw param or NULL — validated at code time */
  char *period;         /* raw param or NULL */
  char *counter_raw;    /* raw param or NULL */
  guint64 counter;
};

/* --- parsing (otp_parse_uri, lines 45–85) ---------------------------------- */

static gboolean
all_digits (const char *s)
{
  if (s == NULL || *s == '\0')
    return FALSE;
  for (; *s != '\0'; s++)
    if (!g_ascii_isdigit (*s))
      return FALSE;
  return TRUE;
}

PassflOtp *
passfl_otp_parse (const char *line, GError **error)
{
  PassflOtp *otp;
  const char *p;
  g_autofree char *label = NULL;
  g_autofree char *m4 = NULL;   /* label before ':' */
  g_autofree char *m6 = NULL;   /* label after ':' */
  const char *query;
  g_auto (GStrv) params = NULL;
  g_autofree char *secret = NULL;

  g_return_val_if_fail (line != NULL, NULL);

  otp = g_new0 (PassflOtp, 1);
  otp->uri = g_strdup (line);

  if (g_str_has_prefix (line, "otpauth://totp"))
    {
      otp->type = PASSFL_OTP_TOTP;
      p = line + strlen ("otpauth://totp");
    }
  else if (g_str_has_prefix (line, "otpauth://hotp"))
    {
      otp->type = PASSFL_OTP_HOTP;
      p = line + strlen ("otpauth://hotp");
    }
  else
    goto bad_uri;

  /* optional /label up to '?' */
  if (*p == '/')
    {
      const char *q = strchr (p, '?');

      if (q == NULL)
        goto bad_uri;
      label = g_strndup (p + 1, (gsize) (q - p - 1));
      p = q;
    }
  if (*p != '?' || p[1] == '\0')
    goto bad_uri;
  query = p + 1;

  if (label != NULL)
    {
      char *colon = strchr (label, ':');

      if (colon != NULL)
        {
          if (strchr (colon + 1, ':') != NULL)
            goto bad_uri; /* the regex allows at most one ':' */
          m4 = g_strndup (label, (gsize) (colon - label));
          m6 = g_strdup (colon + 1);
        }
      else
        m4 = g_strdup (label);
    }

  /* line 59: account from the part after ':', else the whole label —
   * and when both exist, the first part is the issuer */
  if (m6 != NULL && *m6 != '\0')
    {
      otp->account = g_uri_unescape_string (m6, NULL);
      if (m4 != NULL && *m4 != '\0')
        otp->issuer = g_uri_unescape_string (m4, NULL);
    }
  else if (m4 != NULL && *m4 != '\0')
    otp->account = g_uri_unescape_string (m4, NULL);
  if (otp->account == NULL || *otp->account == '\0')
    {
      g_set_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_URI,
                   "Invalid key URI (missing accountname): %s", line);
      passfl_otp_free (otp);
      return NULL;
    }

  params = g_strsplit (query, "&", -1);
  for (guint i = 0; params[i] != NULL; i++)
    {
      char *eq = strchr (params[i], '=');
      const char *value;

      if (eq == NULL || eq == params[i] || eq[1] == '\0')
        continue; /* the (.+) of the param regex — ignore otherwise */
      *eq = '\0';
      value = eq + 1;
      if (strcmp (params[i], "secret") == 0)
        {
          g_free (secret);
          secret = g_strdup (value);
        }
      else if (strcmp (params[i], "digits") == 0)
        {
          g_free (otp->digits);
          otp->digits = g_strdup (value);
        }
      else if (strcmp (params[i], "algorithm") == 0)
        {
          g_free (otp->algorithm);
          otp->algorithm = g_strdup (value);
        }
      else if (strcmp (params[i], "period") == 0)
        {
          g_free (otp->period);
          otp->period = g_strdup (value);
        }
      else if (strcmp (params[i], "counter") == 0)
        {
          g_free (otp->counter_raw);
          otp->counter_raw = g_strdup (value);
        }
      else if (strcmp (params[i], "issuer") == 0)
        {
          g_free (otp->issuer);
          otp->issuer = g_uri_unescape_string (value, NULL);
        }
    }

  if (secret == NULL)
    {
      g_set_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_URI,
                   "Invalid key URI (missing secret): %s", line);
      passfl_otp_free (otp);
      return NULL;
    }
  otp->secret = passfl_secbuf_new (secret, -1);
  explicit_bzero (secret, strlen (secret));

  if (otp->type == PASSFL_OTP_HOTP)
    {
      if (!all_digits (otp->counter_raw))
        {
          g_set_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_URI,
                       "Invalid key URI (missing counter): %s", line);
          passfl_otp_free (otp);
          return NULL;
        }
      otp->counter = g_ascii_strtoull (otp->counter_raw, NULL, 10);
    }
  return otp;

bad_uri:
  g_set_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_URI,
               "Cannot parse OTP key URI: %s", line);
  passfl_otp_free (otp);
  return NULL;
}

void
passfl_otp_free (PassflOtp *otp)
{
  if (otp == NULL)
    return;
  g_free (otp->uri);
  g_free (otp->issuer);
  g_free (otp->account);
  g_clear_pointer (&otp->secret, passfl_secbuf_free);
  g_free (otp->algorithm);
  g_free (otp->digits);
  g_free (otp->period);
  g_free (otp->counter_raw);
  g_free (otp);
}

PassflOtpType
passfl_otp_type (const PassflOtp *otp)
{
  g_return_val_if_fail (otp != NULL, PASSFL_OTP_TOTP);
  return otp->type;
}

const char *
passfl_otp_display (const PassflOtp *otp)
{
  g_return_val_if_fail (otp != NULL, NULL);
  return otp->account;
}

guint
passfl_otp_period (const PassflOtp *otp)
{
  g_return_val_if_fail (otp != NULL, 30);

  if (all_digits (otp->period))
    {
      guint64 v = g_ascii_strtoull (otp->period, NULL, 10);

      if (v >= 1 && v <= 3600)
        return (guint) v;
    }
  return 30; /* oathtool's default time step */
}

guint64
passfl_otp_counter (const PassflOtp *otp)
{
  g_return_val_if_fail (otp != NULL, 0);
  return otp->counter;
}

guint
passfl_otp_remaining (const PassflOtp *otp, gint64 now)
{
  guint period = passfl_otp_period (otp);

  return period - (guint) (((guint64) now) % period);
}

/* --- code generation -------------------------------------------------------- */

/* RFC 4648 base32 into secure memory; tolerant of case, '=' padding and
 * spaces, like oathtool -b. */
static PassflSecBuf *
base32_decode (const char *in, GError **error)
{
  PassflSecBuf *out = passfl_secbuf_new_sized (strlen (in));
  gsize n = 0;
  guint bits = 0;
  guint32 acc = 0;

  for (const char *c = in; *c != '\0'; c++)
    {
      int v;

      if (*c == '=' || *c == ' ')
        continue;
      if (*c >= 'A' && *c <= 'Z')
        v = *c - 'A';
      else if (*c >= 'a' && *c <= 'z')
        v = *c - 'a';
      else if (*c >= '2' && *c <= '7')
        v = *c - '2' + 26;
      else
        {
          passfl_secbuf_free (out);
          g_set_error_literal (error, PASSFL_OTP_ERROR,
                               PASSFL_OTP_ERROR_CODE,
                               "OTP secret is not valid base32");
          return NULL;
        }
      acc = (acc << 5) | (guint32) v;
      bits += 5;
      if (bits >= 8)
        {
          bits -= 8;
          out->data[n++] = (char) ((acc >> bits) & 0xff);
        }
    }
  out->len = n;
  out->data[n] = '\0';
  return out;
}

static char *
hmac_code (const PassflOtp *otp, guint64 counter, GError **error)
{
  int algo = GCRY_MD_SHA1;
  guint digits = 6;
  g_autoptr (PassflSecBuf) key = NULL;
  gcry_md_hd_t hd = NULL;
  guchar msg[8];
  const guchar *digest;
  guint dlen, off;
  guint32 val;
  guint64 mod = 1;

  if (otp->algorithm != NULL)
    {
      if (g_ascii_strcasecmp (otp->algorithm, "SHA1") == 0)
        algo = GCRY_MD_SHA1;
      else if (g_ascii_strcasecmp (otp->algorithm, "SHA256") == 0)
        algo = GCRY_MD_SHA256;
      else if (g_ascii_strcasecmp (otp->algorithm, "SHA512") == 0)
        algo = GCRY_MD_SHA512;
      else
        {
          g_set_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_CODE,
                       "Unsupported OTP algorithm '%s'", otp->algorithm);
          return NULL;
        }
    }
  if (otp->digits != NULL)
    {
      guint64 v = all_digits (otp->digits)
          ? g_ascii_strtoull (otp->digits, NULL, 10)
          : 0;

      if (v < 6 || v > 8) /* what oathtool accepts */
        {
          g_set_error (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_CODE,
                       "Unsupported OTP digits '%s'",
                       otp->digits != NULL ? otp->digits : "");
          return NULL;
        }
      digits = (guint) v;
    }

  key = base32_decode (otp->secret->data, error);
  if (key == NULL)
    return NULL;

  if (gcry_md_open (&hd, algo, GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_SECURE) !=
          0 ||
      gcry_md_setkey (hd, key->data, key->len) != 0)
    {
      if (hd != NULL)
        gcry_md_close (hd);
      g_set_error_literal (error, PASSFL_OTP_ERROR, PASSFL_OTP_ERROR_CODE,
                           "HMAC initialisation failed");
      return NULL;
    }
  for (guint i = 0; i < 8; i++)
    msg[i] = (guchar) (counter >> (56 - 8 * i));
  gcry_md_write (hd, msg, 8);
  digest = gcry_md_read (hd, algo);
  dlen = gcry_md_get_algo_dlen (algo);

  /* RFC 4226 dynamic truncation */
  off = digest[dlen - 1] & 0x0f;
  val = ((guint32) (digest[off] & 0x7f) << 24) |
        ((guint32) digest[off + 1] << 16) |
        ((guint32) digest[off + 2] << 8) | (guint32) digest[off + 3];
  gcry_md_close (hd);

  for (guint i = 0; i < digits; i++)
    mod *= 10;
  return g_strdup_printf ("%0*u", (int) digits,
                          (guint) (val % (guint32) mod));
}

char *
passfl_otp_code (const PassflOtp *otp, gint64 now, GError **error)
{
  g_return_val_if_fail (otp != NULL, NULL);
  g_return_val_if_fail (otp->type == PASSFL_OTP_TOTP, NULL);

  return hmac_code (otp, ((guint64) now) / passfl_otp_period (otp), error);
}

char *
passfl_otp_hotp_code (const PassflOtp *otp, guint64 counter, GError **error)
{
  g_return_val_if_fail (otp != NULL, NULL);
  g_return_val_if_fail (otp->type == PASSFL_OTP_HOTP, NULL);

  return hmac_code (otp, counter, error);
}

char *
passfl_otp_incremented_uri (const PassflOtp *otp)
{
  g_autofree char *old_param = NULL;
  g_autofree char *new_param = NULL;
  GString *uri;

  g_return_val_if_fail (otp != NULL, NULL);
  g_return_val_if_fail (otp->type == PASSFL_OTP_HOTP, NULL);

  /* ${otp_uri/&counter=$otp_counter/&counter=$counter} — first match */
  old_param = g_strdup_printf ("&counter=%s", otp->counter_raw);
  new_param = g_strdup_printf ("&counter=%" G_GUINT64_FORMAT,
                               otp->counter + 1);
  uri = g_string_new (otp->uri);
  {
    const char *hit = strstr (uri->str, old_param);

    if (hit != NULL)
      {
        gsize pos = (gsize) (hit - uri->str);

        g_string_erase (uri, (gssize) pos, (gssize) strlen (old_param));
        g_string_insert (uri, (gssize) pos, new_param);
      }
  }
  return g_string_free (uri, FALSE);
}
