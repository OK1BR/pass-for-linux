/* store.c — tree scan of a pass(1) store, M0 (docs/SPEC.md §2.1, §4.1).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "store.h"

#include <stdlib.h>
#include <string.h>

G_DEFINE_QUARK (passfl-store-error, passfl_store_error)

char *
passfl_store_default_dir (void)
{
  const char *env = g_getenv ("PASSWORD_STORE_DIR");

  /* pass uses ${PASSWORD_STORE_DIR:-…}: empty counts as unset (line 15). */
  if (env != NULL && *env != '\0')
    return g_strdup (env);
  return g_build_filename (g_get_home_dir (), ".password-store", NULL);
}

gboolean
passfl_entry_name_is_safe (const char *name)
{
  g_return_val_if_fail (name != NULL, FALSE);

  g_auto (GStrv) parts = g_strsplit (name, "/", -1);
  for (guint i = 0; parts[i] != NULL; i++)
    if (strcmp (parts[i], "..") == 0)
      return FALSE;
  return TRUE;
}

static PassflNode *
node_new (PassflNodeKind kind, const char *name, const char *rel,
          gboolean is_symlink)
{
  PassflNode *node = g_new0 (PassflNode, 1);

  node->kind = kind;
  node->name = g_strdup (name);
  node->rel = g_strdup (rel);
  node->is_symlink = is_symlink;
  if (kind == PASSFL_NODE_DIR)
    node->children =
        g_ptr_array_new_with_free_func ((GDestroyNotify) passfl_node_free);
  return node;
}

void
passfl_node_free (PassflNode *node)
{
  if (node == NULL)
    return;
  g_free (node->name);
  g_free (node->rel);
  g_clear_pointer (&node->children, g_ptr_array_unref);
  g_free (node);
}

static int
node_cmp (gconstpointer a, gconstpointer b)
{
  const PassflNode *na = *(PassflNode *const *) a;
  const PassflNode *nb = *(PassflNode *const *) b;
  int cmp = strcmp (na->name, nb->name);

  if (cmp != 0)
    return cmp;
  return (int) na->kind - (int) nb->kind; /* directory before entry */
}

/* visited holds realpaths of every directory already scanned, so symlink
 * cycles terminate and diamonds are descended into only once. */
static void
scan_dir (PassflNode *parent, const char *abs, GHashTable *visited)
{
  g_autoptr (GDir) dir = g_dir_open (abs, 0, NULL);
  const char *base;

  if (dir == NULL) /* unreadable subtree: show the node, no children */
    return;

  while ((base = g_dir_read_name (dir)) != NULL)
    {
      g_autofree char *child_abs = NULL;
      gboolean is_symlink;

      if (base[0] == '.') /* .gpg-id, .git, .extensions, … (§2.1) */
        continue;

      child_abs = g_build_filename (abs, base, NULL);
      is_symlink = g_file_test (child_abs, G_FILE_TEST_IS_SYMLINK);

      if (g_file_test (child_abs, G_FILE_TEST_IS_DIR))
        {
          g_autofree char *rel = parent->rel[0] == '\0'
              ? g_strdup (base)
              : g_strconcat (parent->rel, "/", base, NULL);
          PassflNode *child =
              node_new (PASSFL_NODE_DIR, base, rel, is_symlink);
          char *real = realpath (child_abs, NULL);
          gboolean descend = FALSE;

          if (real != NULL)
            {
              descend = g_hash_table_add (visited, g_strdup (real));
              free (real);
            }
          if (descend)
            scan_dir (child, child_abs, visited);
          g_ptr_array_add (parent->children, child);
        }
      else if (g_str_has_suffix (base, ".gpg") &&
               g_file_test (child_abs, G_FILE_TEST_IS_REGULAR))
        {
          g_autofree char *name = g_strndup (base, strlen (base) - 4);
          g_autofree char *rel = parent->rel[0] == '\0'
              ? g_strdup (name)
              : g_strconcat (parent->rel, "/", name, NULL);

          g_ptr_array_add (parent->children,
                           node_new (PASSFL_NODE_ENTRY, name, rel,
                                     is_symlink));
        }
      /* Anything else (stray files, dangling symlinks) is not an entry. */
    }

  g_ptr_array_sort (parent->children, node_cmp);
}

PassflNode *
passfl_store_scan (const char *root, GError **error)
{
  g_return_val_if_fail (root != NULL, NULL);

  g_autoptr (GHashTable) visited =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  PassflNode *node;
  char *real;

  if (!g_file_test (root, G_FILE_TEST_IS_DIR))
    {
      g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_SCAN,
                   "Password store '%s' is not a directory", root);
      return NULL;
    }

  node = node_new (PASSFL_NODE_DIR, "", "",
                   g_file_test (root, G_FILE_TEST_IS_SYMLINK));
  real = realpath (root, NULL);
  if (real != NULL)
    {
      g_hash_table_add (visited, g_strdup (real));
      free (real);
    }
  scan_dir (node, root, visited);
  return node;
}

static void
collect_entries (const PassflNode *node, GPtrArray *out)
{
  if (node->kind == PASSFL_NODE_ENTRY)
    {
      g_ptr_array_add (out, g_strdup (node->rel));
      return;
    }
  for (guint i = 0; i < node->children->len; i++)
    collect_entries (g_ptr_array_index (node->children, i), out);
}

GPtrArray *
passfl_store_list_entries (const char *root, GError **error)
{
  PassflNode *tree = passfl_store_scan (root, error);
  GPtrArray *out;

  if (tree == NULL)
    return NULL;
  out = g_ptr_array_new_with_free_func (g_free);
  collect_entries (tree, out);
  passfl_node_free (tree);
  return out;
}
