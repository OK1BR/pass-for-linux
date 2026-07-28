/* otp.h — otpauth:// parsing and native OTP codes (M5, SPEC §2.3).
 *
 * Faithful to pass-otp 1.2.0 (otp.bash): the URI regex of otp_parse_uri
 * (lines 45–85) including its label/issuer/account rules, oathtool's
 * defaults (SHA1, period 30, 6 digits) applied only when the URI omits
 * the parameter, and the counter+1 convention for HOTP. Codes are
 * computed with libgcrypt HMAC in secure memory — no oathtool, no
 * subprocess. The base32 secret never leaves gcry_malloc_secure().
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_OTP_H
#define PASSFL_OTP_H

#include <glib.h>

G_BEGIN_DECLS

#define PASSFL_OTP_ERROR passfl_otp_error_quark ()
GQuark passfl_otp_error_quark (void);

typedef enum {
  PASSFL_OTP_ERROR_URI,     /* cannot parse / missing secret / counter */
  PASSFL_OTP_ERROR_CODE,    /* bad base32, digits, algorithm, … */
} PassflOtpError;

typedef enum {
  PASSFL_OTP_TOTP,
  PASSFL_OTP_HOTP,
} PassflOtpType;

typedef struct _PassflOtp PassflOtp;

/* Parse one otpauth:// line. Errors mirror pass-otp's checks: secret is
 * required, an account name must be derivable from the label, HOTP needs
 * a numeric counter. */
PassflOtp *passfl_otp_parse (const char *line, GError **error);
void       passfl_otp_free (PassflOtp *otp);

PassflOtpType passfl_otp_type (const PassflOtp *otp);
/* "issuer: account", "account", … — for display. NULL when unnamed. */
const char *passfl_otp_display (const PassflOtp *otp);
guint       passfl_otp_period (const PassflOtp *otp);   /* TOTP */
guint64     passfl_otp_counter (const PassflOtp *otp);  /* HOTP */

/* Seconds until the current TOTP code rolls over. */
guint passfl_otp_remaining (const PassflOtp *otp, gint64 now);

/* The TOTP code at unix time now. Caller frees. */
char *passfl_otp_code (const PassflOtp *otp, gint64 now, GError **error);

/* The HOTP code at an explicit counter value (pass-otp uses the stored
 * counter + 1 and then rewrites the entry — see incremented_uri). */
char *passfl_otp_hotp_code (const PassflOtp *otp, guint64 counter,
                            GError **error);

/* The URI line with `counter=N` replaced by `counter=N+1` — what
 * pass-otp writes back after generating (otp.bash line 360). */
char *passfl_otp_incremented_uri (const PassflOtp *otp);

G_END_DECLS

#endif /* PASSFL_OTP_H */
