/* recipients.c — .gpg-id resolution, M0 (docs/SPEC.md §2.2).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "recipients.h"
#include "crypto.h"
#include "store.h"

#include <string.h>

G_DEFINE_QUARK (passfl-recipients-error, passfl_recipients_error)

GStrv
passfl_gpg_id_parse (const char *content)
{
  g_autoptr (GStrvBuilder) builder = g_strv_builder_new ();
  g_auto (GStrv) lines = NULL;

  g_return_val_if_fail (content != NULL, NULL);

  lines = g_strsplit (content, "\n", -1);
  for (guint i = 0; lines[i] != NULL; i++)
    {
      char *hash = strchr (lines[i], '#'); /* strip comment (line 103) */

      if (hash != NULL)
        *hash = '\0';
      g_strstrip (lines[i]);
      if (*lines[i] != '\0')
        g_strv_builder_add (builder, lines[i]);
    }
  return g_strv_builder_end (builder);
}

/* $PASSWORD_STORE_KEY, whitespace-split like the unquoted expansion at
 * line 75. Non-empty value → nothing else is consulted at all. */
static GStrv
env_key_recipients (void)
{
  const char *key = g_getenv ("PASSWORD_STORE_KEY");
  g_autoptr (GStrvBuilder) builder = NULL;
  g_auto (GStrv) parts = NULL;

  if (key == NULL || *key == '\0')
    return NULL;

  builder = g_strv_builder_new ();
  parts = g_strsplit_set (key, " \t\n", -1);
  for (guint i = 0; parts[i] != NULL; i++)
    if (*parts[i] != '\0')
      g_strv_builder_add (builder, parts[i]);
  return g_strv_builder_end (builder);
}

GStrv
passfl_recipients_resolve (const char *root, const char *dir_rel,
                           char **gpg_id_file, GError **error)
{
  g_autofree char *root_norm = NULL;
  g_autofree char *current = NULL;
  GStrv from_env;
  gsize len;

  g_return_val_if_fail (root != NULL, NULL);
  g_return_val_if_fail (dir_rel != NULL, NULL);
  g_return_val_if_fail (!g_path_is_absolute (dir_rel), NULL);

  if (gpg_id_file != NULL)
    *gpg_id_file = NULL;

  if (!passfl_entry_name_is_safe (dir_rel))
    {
      g_set_error (error, PASSFL_RECIPIENTS_ERROR,
                   PASSFL_RECIPIENTS_ERROR_SNEAKY_PATH,
                   "Sneaky path '%s' rejected", dir_rel);
      return NULL;
    }

  from_env = env_key_recipients ();
  if (from_env != NULL)
    return from_env;

  root_norm = g_strdup (root);
  len = strlen (root_norm);
  while (len > 1 && root_norm[len - 1] == '/')
    root_norm[--len] = '\0';

  current = *dir_rel == '\0'
      ? g_strdup (root_norm)
      : g_strconcat (root_norm, "/", dir_rel, NULL);

  /* The walk of lines 82–86: first .gpg-id wins, the root included. */
  for (;;)
    {
      g_autofree char *candidate = g_strconcat (current, "/.gpg-id", NULL);

      if (g_file_test (candidate, G_FILE_TEST_IS_REGULAR))
        {
          g_autofree char *content = NULL;
          GError *read_error = NULL;

          /* §2.4: with PASSWORD_STORE_SIGNING_KEY set the file must
           * carry a valid signature — pass verifies exactly here
           * (verify_file at line 99), and so do we. */
          if (!passfl_crypto_verify_gpg_id (candidate, error))
            return NULL;
          if (!g_file_get_contents (candidate, &content, NULL, &read_error))
            {
              g_set_error (error, PASSFL_RECIPIENTS_ERROR,
                           PASSFL_RECIPIENTS_ERROR_READ,
                           "Cannot read '%s': %s", candidate,
                           read_error->message);
              g_error_free (read_error);
              return NULL;
            }
          if (gpg_id_file != NULL)
            *gpg_id_file = g_steal_pointer (&candidate);
          return passfl_gpg_id_parse (content);
        }

      if (strcmp (current, root_norm) == 0)
        break;
      char *slash = strrchr (current, '/'); /* drop last component, line 84 */
      if (slash == NULL)
        break;
      *slash = '\0';
    }

  g_set_error (error, PASSFL_RECIPIENTS_ERROR,
               PASSFL_RECIPIENTS_ERROR_UNINITIALIZED,
               "Password store '%s' is uninitialised — "
               "you must run: pass init your-gpg-id", root_norm);
  return NULL;
}

/* --- gpg groups (M4, §4.9) ------------------------------------------------- */

/* group definitions from gpg.conf: name → GPtrArray of member strings.
 * gpg reads them from its config file; so do we — the file gpg itself
 * would use: $GNUPGHOME/gpg.conf or ~/.gnupg/gpg.conf. */
static GHashTable *
load_groups (void)
{
  GHashTable *groups =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                             (GDestroyNotify) g_ptr_array_unref);
  const char *home = g_getenv ("GNUPGHOME");
  g_autofree char *conf_path = home != NULL && *home != '\0'
      ? g_build_filename (home, "gpg.conf", NULL)
      : g_build_filename (g_get_home_dir (), ".gnupg", "gpg.conf", NULL);
  g_autofree char *content = NULL;
  g_auto (GStrv) lines = NULL;

  if (!g_file_get_contents (conf_path, &content, NULL, NULL))
    return groups;

  lines = g_strsplit (content, "\n", -1);
  for (guint i = 0; lines[i] != NULL; i++)
    {
      char *line = lines[i];
      char *hash = strchr (line, '#');
      char *eq;
      g_autofree char *name = NULL;
      g_auto (GStrv) members = NULL;
      GPtrArray *list;

      if (hash != NULL)
        *hash = '\0';
      g_strstrip (line);
      if (!g_str_has_prefix (line, "group") ||
          !g_ascii_isspace (line[5]))
        continue;
      eq = strchr (line + 6, '=');
      if (eq == NULL)
        continue;
      name = g_strndup (line + 6, (gsize) (eq - line - 6));
      g_strstrip (name);
      if (*name == '\0')
        continue;

      list = g_hash_table_lookup (groups, name);
      if (list == NULL)
        {
          list = g_ptr_array_new_with_free_func (g_free);
          g_hash_table_insert (groups, g_strdup (name), list);
        }
      members = g_strsplit_set (eq + 1, " \t,", -1);
      for (guint m = 0; members[m] != NULL; m++)
        if (*members[m] != '\0')
          g_ptr_array_add (list, g_strdup (members[m]));
    }
  return groups;
}

GStrv
passfl_recipients_expand_groups (const char *const *recipients)
{
  g_autoptr (GHashTable) groups = NULL;
  g_autoptr (GStrvBuilder) builder = g_strv_builder_new ();

  g_return_val_if_fail (recipients != NULL, NULL);

  groups = load_groups ();
  for (guint i = 0; recipients[i] != NULL; i++)
    {
      GPtrArray *members =
          g_hash_table_lookup (groups, recipients[i]);

      if (members == NULL)
        {
          g_strv_builder_add (builder, recipients[i]);
          continue;
        }
      for (guint m = 0; m < members->len; m++)
        g_strv_builder_add (builder, g_ptr_array_index (members, m));
    }
  return g_strv_builder_end (builder);
}
