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
#include "vcs.h"

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

/* --- re-encryption (M4, §4.10) --------------------------------------------- */

static gboolean
strv_equal0 (GStrv a, GStrv b)
{
  if (a == NULL || b == NULL)
    return a == b;
  return g_strv_equal ((const char *const *) a, (const char *const *) b);
}

/* One file of the §4.10 walk. display is the entry name pass would print. */
static gboolean
reencrypt_one (const char *root, const char *file, const char *display,
               PassflReencProgress progress, gpointer user_data,
               guint *n_changed, GError **error)
{
  g_autofree char *dir_abs = g_path_get_dirname (file);
  g_autofree char *dir_rel = NULL;
  g_auto (GStrv) recipients = NULL;
  g_auto (GStrv) expanded = NULL;
  g_auto (GStrv) desired = NULL;
  g_auto (GStrv) current = NULL;
  PassflSecBuf *plain;
  gboolean ok;

  /* directory of the file relative to the store root (§2.2 resolution
   * always runs against the store, wherever the repo sits) */
  if (strcmp (dir_abs, root) == 0)
    dir_rel = g_strdup ("");
  else if (g_str_has_prefix (dir_abs, root) && dir_abs[strlen (root)] == '/')
    dir_rel = g_strdup (dir_abs + strlen (root) + 1);
  else
    dir_rel = g_strdup ("");

  recipients = passfl_recipients_resolve (root, dir_rel, NULL, error);
  if (recipients == NULL)
    return FALSE;
  expanded =
      passfl_recipients_expand_groups ((const char *const *) recipients);
  desired =
      passfl_crypto_desired_keyids ((const char *const *) expanded, error);
  if (desired == NULL)
    return FALSE;
  current = passfl_crypto_file_keyids (file, error);
  if (current == NULL)
    return FALSE;

  if (strv_equal0 (desired, current))
    return TRUE; /* step 5: sets match — leave the file alone */

  if (progress != NULL && !progress (display, user_data))
    {
      g_set_error_literal (error, PASSFL_STORE_ERROR,
                           PASSFL_STORE_ERROR_CANCELLED,
                           "Re-encryption cancelled");
      return FALSE;
    }

  plain = passfl_crypto_decrypt_file (file, error);
  if (plain == NULL)
    return FALSE;
  ok = passfl_crypto_encrypt_file (file, plain->data, plain->len,
                                   (const char *const *) expanded, error);
  passfl_secbuf_free (plain);
  if (ok && n_changed != NULL)
    (*n_changed)++;
  return ok;
}

static gboolean
reencrypt_walk (const char *root, const char *abs,
                PassflReencProgress progress, gpointer user_data,
                guint *n_changed, GError **error)
{
  g_autoptr (GDir) dir = NULL;
  const char *base;

  if (g_file_test (abs, G_FILE_TEST_IS_SYMLINK))
    return TRUE; /* line 114: symlinks are skipped */

  if (g_file_test (abs, G_FILE_TEST_IS_REGULAR))
    {
      g_autofree char *lower = g_ascii_strdown (abs, -1);
      g_autofree char *display = NULL;

      if (!g_str_has_suffix (lower, ".gpg")) /* find -iname '*.gpg' */
        return TRUE;
      display = g_str_has_prefix (abs, root) && abs[strlen (root)] == '/'
          ? g_strndup (abs + strlen (root) + 1,
                       strlen (abs) - strlen (root) - 1 - 4)
          : g_strdup (abs);
      return reencrypt_one (root, abs, display, progress, user_data,
                            n_changed, error);
    }

  if (!g_file_test (abs, G_FILE_TEST_IS_DIR))
    return TRUE;

  dir = g_dir_open (abs, 0, NULL);
  if (dir == NULL)
    return TRUE;
  while ((base = g_dir_read_name (dir)) != NULL)
    {
      g_autofree char *child = NULL;

      if (strcmp (base, ".git") == 0) /* the find -prune of .git dirs */
        continue;
      child = g_build_filename (abs, base, NULL);
      if (!reencrypt_walk (root, child, progress, user_data, n_changed,
                           error))
        return FALSE;
    }
  return TRUE;
}

gboolean
passfl_store_reencrypt (const char *root, const char *target,
                        PassflReencProgress progress, gpointer user_data,
                        guint *n_changed, GError **error)
{
  g_return_val_if_fail (root != NULL, FALSE);
  g_return_val_if_fail (target != NULL, FALSE);

  if (n_changed != NULL)
    *n_changed = 0;
  return reencrypt_walk (root, target, progress, user_data, n_changed,
                         error);
}

gboolean
passfl_store_entry_needs_reencrypt (const char *root, const char *name,
                                    gboolean *needed, GError **error)
{
  g_autofree char *path = NULL;
  g_autofree char *dir_rel = NULL;
  g_auto (GStrv) recipients = NULL;
  g_auto (GStrv) expanded = NULL;
  g_auto (GStrv) desired = NULL;
  g_auto (GStrv) current = NULL;
  char *slash;

  g_return_val_if_fail (needed != NULL, FALSE);

  *needed = FALSE;
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
  expanded =
      passfl_recipients_expand_groups ((const char *const *) recipients);
  desired =
      passfl_crypto_desired_keyids ((const char *const *) expanded, error);
  current = passfl_crypto_file_keyids (path, error);
  if (desired == NULL || current == NULL)
    return FALSE;
  *needed = !strv_equal0 (desired, current);
  return TRUE;
}

/* --- mv / cp (M4, §4.9, cmd_copy_move lines 596–649) ----------------------- */

static gboolean
copy_tree (const char *src, const char *dst, GError **error)
{
  mode_t dir_mode = (mode_t) (0777 & ~store_umask ());
  mode_t file_mode = (mode_t) (0666 & ~store_umask ());

  if (g_file_test (src, G_FILE_TEST_IS_DIR))
    {
      g_autoptr (GDir) dir = g_dir_open (src, 0, NULL);
      const char *base;

      if (!g_file_test (dst, G_FILE_TEST_IS_DIR))
        {
          if (g_mkdir (dst, 0700) != 0 || g_chmod (dst, dir_mode) != 0)
            {
              g_set_error (error, PASSFL_STORE_ERROR,
                           PASSFL_STORE_ERROR_WRITE,
                           "Cannot create '%s': %s", dst,
                           g_strerror (errno));
              return FALSE;
            }
        }
      if (dir == NULL)
        return TRUE;
      while ((base = g_dir_read_name (dir)) != NULL)
        {
          g_autofree char *s = g_build_filename (src, base, NULL);
          g_autofree char *d = g_build_filename (dst, base, NULL);

          if (!copy_tree (s, d, error))
            return FALSE;
        }
      return TRUE;
    }

  {
    g_autofree char *content = NULL;
    gsize len = 0;

    if (!g_file_get_contents (src, &content, &len, NULL) ||
        !g_file_set_contents (dst, content, (gssize) len, NULL) ||
        g_chmod (dst, file_mode) != 0)
      {
        g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_WRITE,
                     "Cannot copy '%s' to '%s'", src, dst);
        return FALSE;
      }
  }
  return TRUE;
}

static void
prune_dirs (const char *root, const char *from_dir)
{
  g_autofree char *root_real = NULL;
  char *dir = g_strdup (from_dir);

  {
    char *rr = realpath (root, NULL);

    root_real = rr != NULL ? g_strdup (rr) : g_strdup (root);
    free (rr);
  }
  while (TRUE)
    {
      char *dir_real = realpath (dir, NULL);
      gboolean at_root =
          dir_real != NULL && strcmp (dir_real, root_real) == 0;
      char *parent;

      free (dir_real);
      if (at_root || g_rmdir (dir) != 0)
        break;
      parent = g_path_get_dirname (dir);
      g_free (dir);
      dir = parent;
    }
  g_free (dir);
}

/* The path computation of lines 609–621, shared by mv and cp. */
static gboolean
copy_move_paths (const char *root, const char *old_arg, const char *new_arg,
                 char **old_path_out, char **old_dir_out, char **new_path_out,
                 char **dest_out, GError **error)
{
  g_autofree char *old_stripped = g_strdup (old_arg);
  g_autofree char *old_path = NULL;
  g_autofree char *old_dir = NULL;
  g_autofree char *new_path = NULL;
  g_autofree char *new_parent = NULL;
  g_autofree char *gpg_probe = NULL;
  gboolean old_is_file;
  char *dest;

  if (!passfl_entry_name_is_safe (old_arg) ||
      !passfl_entry_name_is_safe (new_arg))
    {
      g_set_error_literal (error, PASSFL_STORE_ERROR,
                           PASSFL_STORE_ERROR_SNEAKY_PATH,
                           "Sneaky path rejected");
      return FALSE;
    }

  while (g_str_has_suffix (old_stripped, "/"))
    old_stripped[strlen (old_stripped) - 1] = '\0';
  old_path = g_strconcat (root, "/", old_stripped, NULL);
  old_dir = g_strdup (old_path);
  gpg_probe = g_strconcat (old_path, ".gpg", NULL);

  /* line 613: a .gpg file wins unless the path is also a directory and
   * the argument carried a trailing slash */
  old_is_file = g_file_test (gpg_probe, G_FILE_TEST_IS_REGULAR) &&
                !(g_file_test (old_path, G_FILE_TEST_IS_DIR) &&
                  g_str_has_suffix (old_arg, "/"));
  if (old_is_file)
    {
      g_free (old_dir);
      old_dir = g_path_get_dirname (old_path);
      g_free (old_path);
      old_path = g_steal_pointer (&gpg_probe);
    }
  if (!g_file_test (old_path, G_FILE_TEST_EXISTS))
    {
      g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_NOT_FOUND,
                   "%s is not in the password store.", old_arg);
      return FALSE;
    }

  new_path = g_strconcat (root, "/", new_arg, NULL);
  new_parent = g_path_get_dirname (new_path);
  if (!make_parents (root,
                     new_arg, /* creates every dir above the last part */
                     error))
    return FALSE;
  (void) new_parent;

  /* line 621 */
  if (!(g_file_test (old_path, G_FILE_TEST_IS_DIR) ||
        g_file_test (new_path, G_FILE_TEST_IS_DIR) ||
        g_str_has_suffix (new_arg, "/")))
    {
      char *with_gpg = g_strconcat (new_path, ".gpg", NULL);

      g_free (new_path);
      new_path = with_gpg;
    }

  /* mv/cp into an existing directory lands basename inside it */
  if (g_file_test (new_path, G_FILE_TEST_IS_DIR))
    {
      g_autofree char *base = g_path_get_basename (old_path);

      dest = g_build_filename (new_path, base, NULL);
    }
  else
    dest = g_strdup (new_path);

  *old_path_out = g_steal_pointer (&old_path);
  *old_dir_out = g_steal_pointer (&old_dir);
  *new_path_out = g_steal_pointer (&new_path);
  *dest_out = dest;
  return TRUE;
}

static gboolean
copy_move (const char *root, const char *old_arg, const char *new_arg,
           gboolean is_move, gboolean force, PassflReencProgress progress,
           gpointer user_data, GError **error)
{
  g_autofree char *old_path = NULL;
  g_autofree char *old_dir = NULL;
  g_autofree char *new_path = NULL;
  g_autofree char *dest = NULL;
  PassflVcs *vcs_new = NULL;
  gboolean ok = FALSE;

  g_return_val_if_fail (root != NULL, FALSE);
  g_return_val_if_fail (old_arg != NULL && *old_arg != '\0', FALSE);
  g_return_val_if_fail (new_arg != NULL && *new_arg != '\0', FALSE);

  if (!copy_move_paths (root, old_arg, new_arg, &old_path, &old_dir,
                        &new_path, &dest, error))
    return FALSE;

  if (!force && g_file_test (dest, G_FILE_TEST_EXISTS))
    {
      g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_EXISTS,
                   "%s already exists.", dest);
      return FALSE;
    }

  if (is_move)
    {
      if (g_rename (old_path, dest) != 0)
        {
          g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_WRITE,
                       "Cannot move '%s' to '%s': %s", old_path, dest,
                       g_strerror (errno));
          return FALSE;
        }
    }
  else if (!copy_tree (old_path, dest, error))
    return FALSE;

  if (!passfl_store_reencrypt (root, new_path, progress, user_data, NULL,
                               error))
    goto out; /* moved/copied but not reencrypted — error reports it */

  vcs_new = passfl_vcs_open (root, new_path, NULL);
  if (is_move)
    {
      g_autofree char *message = passfl_vcs_msg_rename (old_arg, new_arg);

      if (vcs_new != NULL)
        {
          const char *paths[] = { old_path, new_path, NULL };

          if (!passfl_vcs_commit_paths (vcs_new, paths, message, error))
            goto out;
        }
      /* the old side may live in a different repository (lines 637–642) */
      {
        PassflVcs *vcs_old = passfl_vcs_open (root, old_path, NULL);

        if (vcs_old != NULL &&
            (vcs_new == NULL ||
             strcmp (passfl_vcs_workdir (vcs_old),
                     passfl_vcs_workdir (vcs_new)) != 0))
          {
            g_autofree char *rm_message = passfl_vcs_msg_remove (old_arg);
            const char *paths[] = { old_path, NULL };

            if (!passfl_vcs_commit_paths (vcs_old, paths, rm_message,
                                          error))
              {
                passfl_vcs_free (vcs_old);
                goto out;
              }
          }
        passfl_vcs_free (vcs_old);
      }
      prune_dirs (root, old_dir);
    }
  else
    {
      g_autofree char *message = passfl_vcs_msg_copy (old_arg, new_arg);

      if (vcs_new != NULL)
        {
          const char *paths[] = { new_path, NULL };

          if (!passfl_vcs_commit_paths (vcs_new, paths, message, error))
            goto out;
        }
    }
  ok = TRUE;

out:
  passfl_vcs_free (vcs_new);
  return ok;
}

gboolean
passfl_store_move (const char *root, const char *old_arg,
                   const char *new_arg, gboolean force,
                   PassflReencProgress progress, gpointer user_data,
                   GError **error)
{
  return copy_move (root, old_arg, new_arg, TRUE, force, progress,
                    user_data, error);
}

gboolean
passfl_store_copy (const char *root, const char *old_arg,
                   const char *new_arg, gboolean force,
                   PassflReencProgress progress, gpointer user_data,
                   GError **error)
{
  return copy_move (root, old_arg, new_arg, FALSE, force, progress,
                    user_data, error);
}

/* --- init / deinit (M4, cmd_init lines 320–365) ---------------------------- */

static gboolean
write_plain_file (const char *path, const char *content, gsize len,
                  GError **error)
{
  mode_t mode = (mode_t) (0666 & ~store_umask ());

  if (!g_file_set_contents (path, content, (gssize) len, NULL) ||
      g_chmod (path, mode) != 0)
    {
      g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_WRITE,
                   "Cannot write '%s'", path);
      return FALSE;
    }
  return TRUE;
}

gboolean
passfl_store_init_ids (const char *root, const char *subpath,
                       const char *const *ids,
                       PassflReencProgress progress, gpointer user_data,
                       GError **error)
{
  g_autofree char *dir_abs = NULL;
  g_autofree char *gpg_id = NULL;
  g_autofree char *ids_joined = NULL;
  g_autofree char *target = NULL;
  PassflVcs *vcs = NULL;
  gboolean deinit;
  gboolean ok = FALSE;

  g_return_val_if_fail (root != NULL, FALSE);
  g_return_val_if_fail (subpath != NULL, FALSE);

  if (*subpath != '\0' && !passfl_entry_name_is_safe (subpath))
    {
      g_set_error_literal (error, PASSFL_STORE_ERROR,
                           PASSFL_STORE_ERROR_SNEAKY_PATH,
                           "Sneaky path rejected");
      return FALSE;
    }

  deinit = ids == NULL || ids[0] == NULL ||
           (ids[1] == NULL && *ids[0] == '\0');
  dir_abs = *subpath != '\0' ? g_strconcat (root, "/", subpath, NULL)
                             : g_strdup (root);
  /* pass builds "$PREFIX/$id_path/.gpg-id" — with an empty subpath that
   * is "PREFIX//.gpg-id"; normalise to one slash */
  gpg_id = g_build_filename (dir_abs, ".gpg-id", NULL);
  vcs = passfl_vcs_open (root, gpg_id, NULL);

  if (deinit)
    {
      g_autofree char *message = NULL;

      if (!g_file_test (gpg_id, G_FILE_TEST_IS_REGULAR))
        {
          g_set_error (error, PASSFL_STORE_ERROR,
                       PASSFL_STORE_ERROR_NOT_FOUND,
                       "%s does not exist and so cannot be removed.",
                       gpg_id);
          goto out;
        }
      if (g_unlink (gpg_id) != 0)
        {
          g_set_error (error, PASSFL_STORE_ERROR, PASSFL_STORE_ERROR_WRITE,
                       "Cannot remove '%s': %s", gpg_id,
                       g_strerror (errno));
          goto out;
        }
      message = passfl_vcs_msg_deinit (gpg_id, subpath);
      if (vcs != NULL)
        {
          const char *paths[] = { gpg_id, NULL };

          if (!passfl_vcs_commit_paths (vcs, paths, message, error))
            goto out;
        }
      prune_dirs (root, dir_abs);
      ids_joined = g_strdup ("");
    }
  else
    {
      g_autoptr (GString) content = g_string_new (NULL);
      g_autofree char *message = NULL;
      const char *signing = g_getenv ("PASSWORD_STORE_SIGNING_KEY");

      if (!make_parents (root, *subpath != '\0'
                                   ? (gpg_id + strlen (root) + 1)
                                   : ".gpg-id",
                         error))
        goto out;
      for (guint i = 0; ids[i] != NULL; i++)
        g_string_append_printf (content, "%s\n", ids[i]);
      if (!write_plain_file (gpg_id, content->str, content->len, error))
        goto out;

      ids_joined = g_strjoinv (", ", (char **) ids);
      message = passfl_vcs_msg_set_gpg_id (ids_joined, subpath);
      if (vcs != NULL)
        {
          const char *paths[] = { gpg_id, NULL };

          if (!passfl_vcs_commit_paths (vcs, paths, message, error))
            goto out;
        }

      if (signing != NULL && *signing != '\0')
        {
          g_auto (GStrv) keys = g_strsplit_set (signing, " \t\n", -1);
          const char *signer = NULL;
          g_autoptr (GBytes) sig = NULL;
          g_autofree char *sig_path = g_strconcat (gpg_id, ".sig", NULL);
          g_auto (GStrv) fprs = NULL;
          g_autofree char *fprs_joined = NULL;
          g_autofree char *sign_message = NULL;

          for (guint i = 0; keys[i] != NULL; i++)
            if (*keys[i] != '\0')
              signer = keys[i]; /* gpg keeps the last --default-key */
          sig = passfl_crypto_sign_detached (content->str, content->len,
                                             signer, FALSE, error);
          if (sig == NULL ||
              !write_plain_file (sig_path, g_bytes_get_data (sig, NULL),
                                 g_bytes_get_size (sig), error))
            goto out;
          fprs = passfl_crypto_sig_fingerprints (gpg_id, error);
          if (fprs == NULL || fprs[0] == NULL)
            {
              if (error != NULL && *error == NULL)
                g_set_error_literal (error, PASSFL_STORE_ERROR,
                                     PASSFL_STORE_ERROR_WRITE,
                                     "Signing of .gpg_id unsuccessful.");
              goto out;
            }
          fprs_joined = g_strjoinv (",", fprs);
          sign_message = passfl_vcs_msg_sign_gpg_id (fprs_joined);
          if (vcs != NULL)
            {
              const char *paths[] = { sig_path, NULL };

              if (!passfl_vcs_commit_paths (vcs, paths, sign_message,
                                            error))
                goto out;
            }
        }
    }

  /* the common tail (lines 363–364): reencrypt and commit, on init and
   * deinit alike */
  target = g_strdup (dir_abs);
  if (!passfl_store_reencrypt (root, target, progress, user_data, NULL,
                               error))
    goto out;
  {
    g_autofree char *message =
        passfl_vcs_msg_reencrypt (ids_joined, subpath);
    PassflVcs *vcs_tail = passfl_vcs_open (root, gpg_id, NULL);

    if (vcs_tail != NULL)
      {
        const char *paths[] = { target, NULL };
        gboolean committed =
            passfl_vcs_commit_paths (vcs_tail, paths, message, error);

        passfl_vcs_free (vcs_tail);
        if (!committed)
          goto out;
      }
  }
  ok = TRUE;

out:
  passfl_vcs_free (vcs);
  return ok;
}
