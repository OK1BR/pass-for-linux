/* store.c — tree scan of a pass(1) store, M0 (docs/SPEC.md §2.1, §4.1).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "store.h"

#include <errno.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "crypto.h"
#include "recipients.h"

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

/* --- writes (M2) ---------------------------------------------------------- */

char *
passfl_store_entry_path (const char *root, const char *name, GError **error)
{
  g_return_val_if_fail (root != NULL, NULL);
  g_return_val_if_fail (name != NULL && *name != '\0', NULL);
  g_return_val_if_fail (!g_path_is_absolute (name), NULL);

  if (!passfl_entry_name_is_safe (name))
    {
      g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_SNEAKY_PATH,
                   "Sneaky entry name '%s' rejected", name);
      return NULL;
    }
  return g_strconcat (root, "/", name, ".gpg", NULL);
}

gboolean
passfl_store_entry_exists (const char *root, const char *name)
{
  g_autofree char *path = passfl_store_entry_path (root, name, NULL);

  return path != NULL && g_file_test (path, G_FILE_TEST_IS_REGULAR);
}

gint64
passfl_store_entry_mtime (const char *root, const char *name)
{
  g_autofree char *path = passfl_store_entry_path (root, name, NULL);
  GStatBuf st;

  if (path == NULL || g_stat (path, &st) != 0)
    return -1;
  return (gint64) st.st_mtim.tv_sec * G_USEC_PER_SEC +
         st.st_mtim.tv_nsec / 1000;
}

static guint
store_umask (void)
{
  const char *env = g_getenv ("PASSWORD_STORE_UMASK");
  guint um = 077;

  if (env != NULL && *env != '\0')
    {
      char *end = NULL;
      gulong v = strtoul (env, &end, 8);

      if (end != NULL && *end == '\0' && v <= 0777)
        um = (guint) v;
    }
  return um;
}

/* mkdir -p with 0777 & ~PASSWORD_STORE_UMASK on every directory this
 * call creates (pre-existing ones are left alone, like mkdir -p). */
static gboolean
make_parents (const char *root, const char *name, GError **error)
{
  g_auto (GStrv) parts = g_strsplit (name, "/", -1);
  g_autofree char *current = g_strdup (root);
  mode_t mode = (mode_t) (0777 & ~store_umask ());

  for (guint i = 0; parts[i + 1] != NULL; i++) /* last part is the entry */
    {
      char *next = g_strconcat (current, "/", parts[i], NULL);

      g_free (current);
      current = next;
      if (g_file_test (current, G_FILE_TEST_IS_DIR))
        continue;
      if (g_mkdir (current, 0700) != 0 || g_chmod (current, mode) != 0)
        {
          g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_WRITE,
                       "Cannot create directory '%s': %s", current,
                       g_strerror (errno));
          return FALSE;
        }
    }
  return TRUE;
}

gboolean
passfl_store_write_entry (const char *root, const char *name,
                          const char *data, gsize len, GError **error)
{
  g_autofree char *path = NULL;
  g_autofree char *dir_rel = NULL;
  g_auto (GStrv) recipients = NULL;
  char *slash;

  path = passfl_store_entry_path (root, name, error);
  if (path == NULL)
    return FALSE;

  dir_rel = g_strdup (name);
  slash = strrchr (dir_rel, '/');
  if (slash != NULL)
    *slash = '\0';
  else
    dir_rel[0] = '\0';

  recipients = passfl_recipients_resolve (root, dir_rel, NULL, error);
  if (recipients == NULL)
    return FALSE;

  if (!make_parents (root, name, error))
    return FALSE;
  return passfl_crypto_encrypt_file (path, data, len,
                                     (const char *const *) recipients,
                                     error);
}

gboolean
passfl_store_delete_entry (const char *root, const char *name,
                           GError **error)
{
  g_autofree char *path = passfl_store_entry_path (root, name, error);
  g_autofree char *root_real = NULL;
  g_autofree char *dir = NULL;

  if (path == NULL)
    return FALSE;
  if (!g_file_test (path, G_FILE_TEST_IS_REGULAR))
    {
      g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_NOT_FOUND,
                   "%s is not in the password store.", name);
      return FALSE;
    }
  if (g_unlink (path) != 0)
    {
      g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_WRITE,
                   "Cannot remove '%s': %s", path, g_strerror (errno));
      return FALSE;
    }

  /* rmdir -p (line 593): prune upwards while directories empty out; any
   * failure (non-empty, permissions) simply stops the pruning. */
  {
    char *rr = realpath (root, NULL);

    root_real = rr != NULL ? g_strdup (rr) : g_strdup (root);
    free (rr);
  }
  dir = g_path_get_dirname (path);
  while (TRUE)
    {
      char *dir_real = realpath (dir, NULL);
      gboolean at_root = dir_real != NULL &&
                         strcmp (dir_real, root_real) == 0;
      char *parent;

      free (dir_real);
      if (at_root || g_rmdir (dir) != 0)
        break;
      parent = g_path_get_dirname (dir);
      g_free (dir);
      dir = parent;
    }
  return TRUE;
}

/* --- watch (§7.7) ---------------------------------------------------------- */

struct _PassflWatch {
  char *root;
  PassflWatchFunc cb;
  gpointer user_data;
  GPtrArray *monitors;   /* GFileMonitor, one per directory */
  guint coalesce_id;
};

static gboolean
watch_fire (gpointer data)
{
  PassflWatch *watch = data;

  watch->coalesce_id = 0;
  watch->cb (watch->user_data);
  return G_SOURCE_REMOVE;
}

static void
on_dir_changed (GFileMonitor *monitor, GFile *file, GFile *other,
                GFileMonitorEvent event, gpointer data)
{
  PassflWatch *watch = data;
  g_autofree char *base = g_file_get_basename (file);

  (void) monitor;
  (void) other;
  (void) event;
  /* Our own temp files and .git churn are not store changes. */
  if (base != NULL &&
      (g_str_has_prefix (base, ".passfl.tmp.") || strcmp (base, ".git") == 0))
    return;
  if (watch->coalesce_id == 0)
    watch->coalesce_id = g_timeout_add (400, watch_fire, watch);
}

static void
watch_dir (PassflWatch *watch, const char *abs)
{
  g_autoptr (GFile) file = g_file_new_for_path (abs);
  GFileMonitor *monitor =
      g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);

  if (monitor == NULL)
    return;
  g_signal_connect (monitor, "changed", G_CALLBACK (on_dir_changed), watch);
  g_ptr_array_add (watch->monitors, monitor);
}

static void
watch_add_tree (PassflWatch *watch, const char *abs)
{
  g_autoptr (GDir) dir = g_dir_open (abs, 0, NULL);
  const char *base;

  watch_dir (watch, abs);
  if (dir == NULL)
    return;
  while ((base = g_dir_read_name (dir)) != NULL)
    {
      g_autofree char *child = NULL;

      if (base[0] == '.')
        continue;
      child = g_build_filename (abs, base, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR) &&
          !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        watch_add_tree (watch, child);
    }
}

PassflWatch *
passfl_store_watch_new (const char *root, PassflWatchFunc cb,
                        gpointer user_data)
{
  PassflWatch *watch;

  g_return_val_if_fail (root != NULL, NULL);
  g_return_val_if_fail (cb != NULL, NULL);

  watch = g_new0 (PassflWatch, 1);
  watch->root = g_strdup (root);
  watch->cb = cb;
  watch->user_data = user_data;
  watch->monitors = g_ptr_array_new_with_free_func (g_object_unref);
  watch_add_tree (watch, root);
  return watch;
}

void
passfl_store_watch_rearm (PassflWatch *watch)
{
  g_return_if_fail (watch != NULL);
  g_ptr_array_set_size (watch->monitors, 0);
  watch_add_tree (watch, watch->root);
}

void
passfl_store_watch_free (PassflWatch *watch)
{
  if (watch == NULL)
    return;
  g_clear_handle_id (&watch->coalesce_id, g_source_remove);
  g_ptr_array_unref (watch->monitors);
  g_free (watch->root);
  g_free (watch);
}
