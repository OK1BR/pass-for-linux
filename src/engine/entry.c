/* entry.c — entry content parsing, M1 (docs/SPEC.md §2.3).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "entry.h"
#include "crypto.h"

#include <string.h>

struct _PassflEntry {
  PassflSecBuf *buf;     /* the content with '\n' turned into '\0' */
  GPtrArray *lines;      /* const char* into buf — no free func */
  gboolean final_newline;
};

PassflEntry *
passfl_entry_parse (const char *data, gsize len)
{
  PassflEntry *entry;
  gsize start = 0;

  g_return_val_if_fail (data != NULL || len == 0, NULL);

  entry = g_new0 (PassflEntry, 1);
  entry->buf = passfl_secbuf_new (data, (gssize) len);
  entry->lines = g_ptr_array_new ();
  entry->final_newline = len > 0 && data[len - 1] == '\n';

  for (gsize i = 0; i < len; i++)
    if (entry->buf->data[i] == '\n')
      {
        entry->buf->data[i] = '\0';
        g_ptr_array_add (entry->lines, entry->buf->data + start);
        start = i + 1;
      }
  if (start < len) /* content after the last newline */
    g_ptr_array_add (entry->lines, entry->buf->data + start);

  return entry;
}

void
passfl_entry_free (PassflEntry *entry)
{
  if (entry == NULL)
    return;
  g_ptr_array_unref (entry->lines);
  passfl_secbuf_free (entry->buf);
  g_free (entry);
}

guint
passfl_entry_n_lines (const PassflEntry *entry)
{
  g_return_val_if_fail (entry != NULL, 0);
  return entry->lines->len;
}

const char *
passfl_entry_line (const PassflEntry *entry, guint i)
{
  g_return_val_if_fail (entry != NULL, NULL);
  g_return_val_if_fail (i < entry->lines->len, NULL);
  return g_ptr_array_index (entry->lines, i);
}

gboolean
passfl_entry_final_newline (const PassflEntry *entry)
{
  g_return_val_if_fail (entry != NULL, FALSE);
  return entry->final_newline;
}

const char *
passfl_entry_password (const PassflEntry *entry)
{
  g_return_val_if_fail (entry != NULL, NULL);
  return entry->lines->len > 0 ? g_ptr_array_index (entry->lines, 0) : "";
}

gboolean
passfl_entry_line_kv (const char *line, gsize *key_len, const char **value)
{
  const char *colon;
  const char *val;

  g_return_val_if_fail (line != NULL, FALSE);

  colon = strchr (line, ':');
  if (colon == NULL || colon == line)
    return FALSE;
  val = colon + 1;
  if (val[0] == '/' && val[1] == '/') /* URI, not key: value */
    return FALSE;
  while (*val == ' ' || *val == '\t')
    val++;
  if (key_len != NULL)
    *key_len = (gsize) (colon - line);
  if (value != NULL)
    *value = val;
  return TRUE;
}

gboolean
passfl_entry_line_is_otp (const char *line)
{
  g_return_val_if_fail (line != NULL, FALSE);
  return g_str_has_prefix (line, "otpauth://totp/") ||
         g_str_has_prefix (line, "otpauth://hotp/");
}
