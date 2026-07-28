/* store.h — the password store on disk: tree scan and entry names (M0).
 *
 * A store is a directory of GPG-encrypted files (SPEC §2.1): an entry is a
 * regular file ending in ".gpg", its name the path relative to the store
 * root without the suffix, with literal '/' separators. This module only
 * looks at names — nothing here decrypts anything. Dotfiles (.gpg-id,
 * .git, .extensions, .gitattributes) are format internals and never appear
 * as nodes; other non-.gpg files are not entries and are not listed.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_STORE_H
#define PASSFL_STORE_H

#include <glib.h>

G_BEGIN_DECLS

#define PASSFL_STORE_ERROR passfl_store_error_quark ()
GQuark passfl_store_error_quark (void);

typedef enum {
  PASSFL_STORE_ERROR_SCAN,          /* store root missing or unreadable */
  PASSFL_STORE_ERROR_SNEAKY_PATH,   /* ".." component (SPEC §2.5) */
  PASSFL_STORE_ERROR_WRITE,         /* mkdir/unlink/rename failed */
  PASSFL_STORE_ERROR_NOT_FOUND,     /* entry does not exist */
} PassflStoreError;

/* $PASSWORD_STORE_DIR, or ~/.password-store when unset/empty (SPEC §5).
 * Caller frees. */
char *passfl_store_default_dir (void);

/* TRUE unless any '/'-separated component of name is ".." — pass's
 * check_sneaky_paths (line 145, SPEC §2.5). MUST be applied to every
 * user-supplied entry name before it touches the filesystem. */
gboolean passfl_entry_name_is_safe (const char *name);

typedef enum {
  PASSFL_NODE_DIR,
  PASSFL_NODE_ENTRY,
} PassflNodeKind;

/* One node of the scanned tree. Children are sorted by name, byte order,
 * directories and entries intermixed (a directory wins a name tie). */
typedef struct _PassflNode PassflNode;
struct _PassflNode {
  PassflNodeKind kind;
  char      *name;        /* basename; ".gpg" stripped for entries */
  char      *rel;         /* path relative to the root, "" for the root node */
  gboolean   is_symlink;  /* symlinked entries are read-only (SPEC §2.1) */
  GPtrArray *children;    /* PassflNode*; NULL for entries */
};

/* Scan the tree under root and return the root node (kind DIR, rel "").
 * Symlinked directories are followed once — a directory already scanned
 * (a symlink cycle or diamond) is shown but not descended into again.
 * Dangling symlinks are skipped. */
PassflNode *passfl_store_scan (const char *root, GError **error);
void        passfl_node_free  (PassflNode *node);

/* Flat list of entry names (char*), depth-first in tree order — the order
 * the sidebar shows. Caller frees the array (elements owned by it). */
GPtrArray *passfl_store_list_entries (const char *root, GError **error);

/* root/name.gpg after the §2.5 safety check. Caller frees. */
char *passfl_store_entry_path (const char *root, const char *name,
                               GError **error);

gboolean passfl_store_entry_exists (const char *root, const char *name);

/* Modification time (µs since the epoch) of an entry file, -1 when it
 * does not exist — the §7.7 guard against overwriting a concurrent
 * change blindly. */
gint64 passfl_store_entry_mtime (const char *root, const char *name);

/* Write one entry (SPEC §4.5/§4.6): resolve recipients for its directory
 * (§2.2, with the §2.4 signature check), create missing parents with
 * 0777 & ~PASSWORD_STORE_UMASK, encrypt and atomically replace the file.
 * The store must be initialised — no .gpg-id is a hard error. */
gboolean passfl_store_write_entry (const char *root, const char *name,
                                   const char *data, gsize len,
                                   GError **error);

/* Delete one entry and prune now-empty parent directories up to the
 * store root (`rmdir -p`, line 593 — we stop at the root; pass would
 * walk past it, which only differs on a store with nothing in it). */
gboolean passfl_store_delete_entry (const char *root, const char *name,
                                    GError **error);

/* On-disk change notification: one callback (in the GLib main context
 * that created the watch) whenever anything under root changes, events
 * coalesced. Re-created by rearm after a rescan picks up new
 * directories. Free stops watching. */
typedef struct _PassflWatch PassflWatch;
typedef void (*PassflWatchFunc) (gpointer user_data);

PassflWatch *passfl_store_watch_new (const char *root, PassflWatchFunc cb,
                                     gpointer user_data);
void         passfl_store_watch_rearm (PassflWatch *watch);
void         passfl_store_watch_free (PassflWatch *watch);

G_END_DECLS

#endif /* PASSFL_STORE_H */
