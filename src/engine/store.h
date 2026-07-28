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

G_END_DECLS

#endif /* PASSFL_STORE_H */
