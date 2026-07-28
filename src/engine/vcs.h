/* vcs.h — git through libgit2 (M3, SPEC §6). No git subprocess, ever.
 *
 * The repository is discovered by walking up from the touched file with
 * the store's parent as the ceiling — pass allows a repo rooted at the
 * store root or anywhere between the entry and the root (set_git, lines
 * 30–36), and a store without git is normal. One commit per operation,
 * and only if the file actually changed; messages are part of the §1
 * compatibility contract and come from the builders below.
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#ifndef PASSFL_VCS_H
#define PASSFL_VCS_H

#include <glib.h>

G_BEGIN_DECLS

#define PASSFL_VCS_ERROR passfl_vcs_error_quark ()
GQuark passfl_vcs_error_quark (void);

typedef enum {
  PASSFL_VCS_ERROR_GIT,       /* libgit2 failure, message carries details */
  PASSFL_VCS_ERROR_IDENTITY,  /* user.name / user.email not configured */
} PassflVcsError;

typedef struct _PassflVcs PassflVcs;

/* Discover the repository responsible for path (a file inside the store,
 * existing or just deleted). Returns NULL with no error set when there
 * is none — the store simply is not git-tracked there. */
PassflVcs *passfl_vcs_open (const char *store_root, const char *path,
                            GError **error);
void passfl_vcs_free (PassflVcs *vcs);

/* pass's git_add_file (lines 37–48): stage the file (or its removal),
 * commit iff something actually changed, GPG-sign when the repository
 * has pass.signcommits = true. TRUE also when there was nothing to
 * commit. */
gboolean passfl_vcs_commit_file (PassflVcs *vcs, const char *path,
                                 const char *message, GError **error);

/* Same, over several paths at once (files or directories — a directory
 * stages everything under it, additions and removals alike); used by
 * mv/cp/init where one commit spans multiple staged changes. Commits
 * only when the resulting tree differs from HEAD's. */
gboolean passfl_vcs_commit_paths (PassflVcs *vcs, const char *const *paths,
                                  const char *message, GError **error);

/* The repository work dir (with trailing '/'), to tell two repos apart. */
const char *passfl_vcs_workdir (PassflVcs *vcs);

/* One commit that touched an entry. */
typedef struct {
  char *oid;      /* full hex */
  char *summary;  /* first line of the message */
  gint64 time;    /* committer time, seconds since the epoch */
} PassflVcsCommit;

/* Newest-first commits that changed path (like `git log -- path`, no
 * rename following). Empty array for an untracked file. */
GPtrArray *passfl_vcs_history (PassflVcs *vcs, const char *path,
                               GError **error);

/* The file's ciphertext as of the given commit, NULL when the file did
 * not exist there. */
GBytes *passfl_vcs_file_at (PassflVcs *vcs, const char *oid,
                            const char *path, GError **error);

/* Commit messages of §6, byte-exact where pass's are (the editor name in
 * the edit message is ours by design — SPEC §11.3). Caller frees. */
char *passfl_vcs_msg_insert (const char *name);
char *passfl_vcs_msg_edit (const char *name, gboolean existed);
char *passfl_vcs_msg_generate (const char *name, gboolean in_place);
char *passfl_vcs_msg_remove (const char *name);
char *passfl_vcs_msg_rename (const char *old_arg, const char *new_arg);
char *passfl_vcs_msg_copy (const char *old_arg, const char *new_arg);
/* ids_joined is the ", "-joined id list ("" on deinit — pass's quirky
 * double space before a subpath tag is reproduced); subpath "" = root. */
char *passfl_vcs_msg_set_gpg_id (const char *ids_joined,
                                 const char *subpath);
char *passfl_vcs_msg_deinit (const char *gpg_id_abs, const char *subpath);
char *passfl_vcs_msg_reencrypt (const char *ids_joined,
                                const char *subpath);
char *passfl_vcs_msg_sign_gpg_id (const char *fprs_joined);

G_END_DECLS

#endif /* PASSFL_VCS_H */
