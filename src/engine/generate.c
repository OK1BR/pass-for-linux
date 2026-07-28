/* generate.c — password generation, M2 (docs/SPEC.md §4.8).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "generate.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

G_DEFINE_QUARK (passfl-generate-error, passfl_generate_error)

typedef gboolean (*ClassFunc) (gchar c);

/* g_ascii_is* are macros — wrap them so the table can hold pointers. */
static gboolean is_alnum (gchar c)  { return g_ascii_isalnum (c); }
static gboolean is_alpha (gchar c)  { return g_ascii_isalpha (c); }
static gboolean is_digit (gchar c)  { return g_ascii_isdigit (c); }
static gboolean is_lower (gchar c)  { return g_ascii_islower (c); }
static gboolean is_upper (gchar c)  { return g_ascii_isupper (c); }
static gboolean is_punct (gchar c)  { return g_ascii_ispunct (c); }
static gboolean is_graph (gchar c)  { return g_ascii_isgraph (c); }
static gboolean is_xdigit (gchar c) { return g_ascii_isxdigit (c); }

static const struct {
  const char *name;
  ClassFunc test;
} classes[] = {
  { "alnum", is_alnum },   { "alpha", is_alpha },
  { "digit", is_digit },   { "lower", is_lower },
  { "upper", is_upper },   { "punct", is_punct },
  { "graph", is_graph },   { "xdigit", is_xdigit },
};

static void
set_add (gboolean seen[128], GString *out, gchar c)
{
  if ((guchar) c >= 128 || seen[(guchar) c])
    return;
  seen[(guchar) c] = TRUE;
  g_string_append_c (out, c);
}

char *
passfl_generate_expand_set (const char *set, GError **error)
{
  gboolean seen[128] = { FALSE };
  g_autoptr (GString) out = g_string_new (NULL);
  gsize i = 0, len;

  g_return_val_if_fail (set != NULL, NULL);

  len = strlen (set);
  while (i < len)
    {
      /* [:class:] */
      if (set[i] == '[' && set[i + 1] == ':')
        {
          const char *end = strstr (set + i + 2, ":]");

          if (end != NULL)
            {
              g_autofree char *name =
                  g_strndup (set + i + 2, (gsize) (end - set - i - 2));
              gboolean known = FALSE;

              for (guint c = 0; c < G_N_ELEMENTS (classes); c++)
                if (strcmp (name, classes[c].name) == 0)
                  {
                    for (int ch = 1; ch < 128; ch++)
                      if (classes[c].test ((gchar) ch))
                        set_add (seen, out, (gchar) ch);
                    known = TRUE;
                    break;
                  }
              if (!known)
                {
                  g_set_error (error, PASSFL_GENERATE_ERROR,
                               PASSFL_GENERATE_ERROR_SET,
                               "Unknown character class [:%s:]", name);
                  return NULL;
                }
              i = (gsize) (end - set) + 2;
              continue;
            }
        }
      /* a-z range (a literal '-' at either end stays literal, like tr) */
      if (i + 2 < len && set[i + 1] == '-' && set[i + 2] != '\0' &&
          set[i] != '[' && (guchar) set[i] <= (guchar) set[i + 2])
        {
          for (gchar c = set[i]; c <= set[i + 2]; c++)
            set_add (seen, out, c);
          i += 3;
          continue;
        }
      set_add (seen, out, set[i]);
      i++;
    }

  if (out->len == 0)
    {
      g_set_error (error, PASSFL_GENERATE_ERROR, PASSFL_GENERATE_ERROR_SET,
                   "Character set '%s' expands to nothing", set);
      return NULL;
    }
  return g_strdup (out->str);
}

PassflSecBuf *
passfl_generate_password (guint length, gboolean no_symbols, GError **error)
{
  const char *set_env = no_symbols
      ? g_getenv ("PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS")
      : g_getenv ("PASSWORD_STORE_CHARACTER_SET");
  const char *set_default = no_symbols ? "[:alnum:]" : "[:punct:][:alnum:]";
  g_autofree char *alphabet = NULL;
  PassflSecBuf *buf;
  guint n;

  if (length == 0)
    {
      const char *len_env = g_getenv ("PASSWORD_STORE_GENERATED_LENGTH");
      int v = len_env != NULL ? atoi (len_env) : 0;

      length = v > 0 ? (guint) v : 25;
    }

  alphabet = passfl_generate_expand_set (
      set_env != NULL && *set_env != '\0' ? set_env : set_default, error);
  if (alphabet == NULL)
    return NULL;
  n = (guint) strlen (alphabet);

  buf = passfl_secbuf_new_sized (length);

  /* Rejection sampling: draw a byte, reject anything at or above the
   * largest multiple of n, so every alphabet index is equally likely. */
  {
    guint filled = 0;
    guint limit = 256 - (256 % n);

    while (filled < length)
      {
        guchar rnd[64];
        gssize got = getrandom (rnd, sizeof rnd, 0);

        if (got < 0)
          {
            passfl_secbuf_free (buf);
            g_set_error (error, PASSFL_GENERATE_ERROR,
                         PASSFL_GENERATE_ERROR_RANDOM,
                         "getrandom: %s", g_strerror (errno));
            return NULL;
          }
        for (gssize i = 0; i < got && filled < length; i++)
          if (rnd[i] < limit)
            buf->data[filled++] = alphabet[rnd[i] % n];
      }
    buf->data[length] = '\0';
  }
  return buf;
}
