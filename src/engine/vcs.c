/* vcs.c — git integration, M3 (docs/SPEC.md §6).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "vcs.h"

#include <git2.h>
#include <string.h>

#include "crypto.h"

G_DEFINE_QUARK (passfl-vcs-error, passfl_vcs_error)

struct _PassflVcs {
  git_repository *repo;
  char *workdir; /* with trailing '/' as libgit2 reports it */
};

static void
set_git_error (GError **error, const char *doing)
{
  const git_error *ge = git_error_last ();

  g_set_error (error, PASSFL_VCS_ERROR, PASSFL_VCS_ERROR_GIT, "git: %s: %s",
               doing, ge != NULL ? ge->message : "unknown error");
}

static void
vcs_init_once (void)
{
  static gsize once = 0;

  if (g_once_init_enter (&once))
    {
      git_libgit2_init ();
      g_once_init_leave (&once, 1);
    }
}

PassflVcs *
passfl_vcs_open (const char *store_root, const char *path, GError **error)
{
  g_autofree char *start = NULL;
  g_autofree char *ceiling = NULL;
  git_repository *repo = NULL;
  PassflVcs *vcs;
  int rc;

  g_return_val_if_fail (store_root != NULL, NULL);
  g_return_val_if_fail (path != NULL, NULL);

  vcs_init_once ();

  /* Walk up from the file's directory; never escape past the store's
   * parent (GIT_CEILING_DIRECTORIES = "$PREFIX/..", line 24). */
  start = g_path_get_dirname (path);
  while (!g_file_test (start, G_FILE_TEST_IS_DIR))
    {
      char *up = g_path_get_dirname (start);

      if (strcmp (up, start) == 0) /* hit the filesystem root */
        {
          g_free (up);
          break;
        }
      g_free (start);
      start = up;
    }
  ceiling = g_path_get_dirname (store_root);

  rc = git_repository_open_ext (&repo, start, 0, ceiling);
  if (rc == GIT_ENOTFOUND)
    return NULL; /* not a git store — normal, not an error */
  if (rc != 0)
    {
      set_git_error (error, "open repository");
      return NULL;
    }
  if (git_repository_workdir (repo) == NULL) /* bare — useless here */
    {
      git_repository_free (repo);
      return NULL;
    }

  vcs = g_new0 (PassflVcs, 1);
  vcs->repo = repo;
  vcs->workdir = g_strdup (git_repository_workdir (repo));
  return vcs;
}

void
passfl_vcs_free (PassflVcs *vcs)
{
  if (vcs == NULL)
    return;
  git_repository_free (vcs->repo);
  g_free (vcs->workdir);
  g_free (vcs);
}

/* Path relative to the repository work dir, NULL when outside it. */
static char *
rel_path (PassflVcs *vcs, const char *path)
{
  if (!g_str_has_prefix (path, vcs->workdir))
    return NULL;
  return g_strdup (path + strlen (vcs->workdir));
}

/* HEAD's branch reference name ("refs/heads/…"), for the signed-commit
 * path which has to move the branch itself. */
static char *
head_ref_name (PassflVcs *vcs)
{
  git_reference *head = NULL;
  char *name = NULL;

  if (git_reference_lookup (&head, vcs->repo, "HEAD") != 0)
    return NULL;
  if (git_reference_type (head) == GIT_REFERENCE_SYMBOLIC)
    name = g_strdup (git_reference_symbolic_target (head));
  git_reference_free (head);
  return name;
}

static gboolean
commit_tree (PassflVcs *vcs, git_tree *tree, const char *message,
             GError **error)
{
  git_signature *sig = NULL;
  git_commit *parent = NULL;
  git_oid parent_oid, commit_oid;
  const git_commit *parents[1];
  int n_parents = 0;
  git_config *config = NULL;
  int signcommits = 0;
  gboolean ok = FALSE;

  if (git_signature_default (&sig, vcs->repo) != 0)
    {
      g_set_error_literal (error, PASSFL_VCS_ERROR,
                           PASSFL_VCS_ERROR_IDENTITY,
                           "git user.name / user.email are not configured "
                           "for this repository");
      return FALSE;
    }

  if (git_reference_name_to_id (&parent_oid, vcs->repo, "HEAD") == 0 &&
      git_commit_lookup (&parent, vcs->repo, &parent_oid) == 0)
    {
      parents[0] = parent;
      n_parents = 1;
    }

  /* pass.signcommits (line 46) — a git config bool, default false. A
   * plain `git commit` would also honour commit.gpgsign, so honour both
   * to stay observably equivalent. */
  if (git_repository_config_snapshot (&config, vcs->repo) == 0)
    {
      int gpgsign = 0;

      git_config_get_bool (&signcommits, config, "pass.signcommits");
      git_config_get_bool (&gpgsign, config, "commit.gpgsign");
      signcommits = signcommits || gpgsign;
    }

  if (!signcommits)
    {
      if (git_commit_create (&commit_oid, vcs->repo, "HEAD", sig, sig,
                             NULL, message, tree, n_parents,
                             (const git_commit **) parents) != 0)
        {
          set_git_error (error, "commit");
          goto out;
        }
    }
  else
    {
      git_buf raw = { 0 };
      g_autofree char *signer = NULL;
      g_autoptr (GBytes) sig_bytes = NULL;
      g_autofree char *signature = NULL;
      g_autofree char *branch = NULL;
      const char *signingkey = NULL;
      git_reference *moved = NULL;

      if (config != NULL &&
          git_config_get_string (&signingkey, config, "user.signingkey") ==
              0)
        signer = g_strdup (signingkey);
      else
        signer = g_strdup (sig->email); /* what git -S falls back to */

      if (git_commit_create_buffer (&raw, vcs->repo, sig, sig, NULL,
                                    message, tree, n_parents,
                                    (const git_commit **) parents) != 0)
        {
          set_git_error (error, "build commit");
          goto out;
        }
      sig_bytes = passfl_crypto_sign_detached (raw.ptr, raw.size, signer,
                                               TRUE, error);
      if (sig_bytes == NULL)
        {
          git_buf_dispose (&raw);
          goto out;
        }
      signature = g_strndup (g_bytes_get_data (sig_bytes, NULL),
                             g_bytes_get_size (sig_bytes));
      if (git_commit_create_with_signature (&commit_oid, vcs->repo,
                                            raw.ptr, signature, NULL) != 0)
        {
          git_buf_dispose (&raw);
          set_git_error (error, "signed commit");
          goto out;
        }
      git_buf_dispose (&raw);

      /* create_with_signature does not move the branch — do it. */
      branch = head_ref_name (vcs);
      if (branch == NULL ||
          git_reference_create (&moved, vcs->repo, branch, &commit_oid, 1,
                                message) != 0)
        {
          set_git_error (error, "update branch");
          goto out;
        }
      git_reference_free (moved);
    }
  ok = TRUE;

out:
  if (config != NULL)
    git_config_free (config);
  if (parent != NULL)
    git_commit_free (parent);
  git_signature_free (sig);
  return ok;
}

gboolean
passfl_vcs_commit_file (PassflVcs *vcs, const char *path,
                        const char *message, GError **error)
{
  g_autofree char *rel = NULL;
  git_index *index = NULL;
  git_tree *tree = NULL;
  git_oid tree_oid;
  unsigned int status = 0;
  gboolean ok = FALSE;

  g_return_val_if_fail (vcs != NULL, FALSE);
  g_return_val_if_fail (path != NULL, FALSE);
  g_return_val_if_fail (message != NULL, FALSE);

  rel = rel_path (vcs, path);
  if (rel == NULL)
    {
      g_set_error (error, PASSFL_VCS_ERROR, PASSFL_VCS_ERROR_GIT,
                   "'%s' is outside the repository", path);
      return FALSE;
    }

  if (git_repository_index (&index, vcs->repo) != 0)
    {
      set_git_error (error, "open index");
      return FALSE;
    }

  if (g_file_test (path, G_FILE_TEST_EXISTS))
    {
      if (git_index_add_bypath (index, rel) != 0)
        {
          set_git_error (error, "stage file");
          goto out;
        }
    }
  else if (git_index_remove_bypath (index, rel) != 0)
    {
      set_git_error (error, "stage removal");
      goto out;
    }
  if (git_index_write (index) != 0)
    {
      set_git_error (error, "write index");
      goto out;
    }

  /* The `git status --porcelain` guard (line 40): no change, no commit. */
  if (git_status_file (&status, vcs->repo, rel) == 0 &&
      (status & (GIT_STATUS_INDEX_NEW | GIT_STATUS_INDEX_MODIFIED |
                 GIT_STATUS_INDEX_DELETED | GIT_STATUS_INDEX_RENAMED |
                 GIT_STATUS_INDEX_TYPECHANGE)) == 0)
    {
      ok = TRUE; /* nothing to do */
      goto out;
    }

  if (git_index_write_tree (&tree_oid, index) != 0 ||
      git_tree_lookup (&tree, vcs->repo, &tree_oid) != 0)
    {
      set_git_error (error, "write tree");
      goto out;
    }
  ok = commit_tree (vcs, tree, message, error);

out:
  if (tree != NULL)
    git_tree_free (tree);
  git_index_free (index);
  return ok;
}

/* --- history --------------------------------------------------------------- */

static void
vcs_commit_free (gpointer data)
{
  PassflVcsCommit *c = data;

  g_free (c->oid);
  g_free (c->summary);
  g_free (c);
}

/* Did this commit change rel, compared to its first parent? */
static gboolean
commit_touches (PassflVcs *vcs, git_commit *commit, const char *rel)
{
  git_tree *tree = NULL;
  git_tree *parent_tree = NULL;
  git_commit *parent = NULL;
  git_diff *diff = NULL;
  git_diff_options opts;
  char *paths[1] = { (char *) rel };
  gboolean touched = FALSE;

  git_diff_options_init (&opts, GIT_DIFF_OPTIONS_VERSION);
  opts.pathspec.strings = paths;
  opts.pathspec.count = 1;

  if (git_commit_tree (&tree, commit) != 0)
    return FALSE;
  if (git_commit_parentcount (commit) > 0 &&
      git_commit_parent (&parent, commit, 0) == 0)
    git_commit_tree (&parent_tree, parent);

  if (git_diff_tree_to_tree (&diff, vcs->repo, parent_tree, tree, &opts) ==
      0)
    {
      touched = git_diff_num_deltas (diff) > 0;
      git_diff_free (diff);
    }

  if (parent_tree != NULL)
    git_tree_free (parent_tree);
  if (parent != NULL)
    git_commit_free (parent);
  git_tree_free (tree);
  return touched;
}

GPtrArray *
passfl_vcs_history (PassflVcs *vcs, const char *path, GError **error)
{
  g_autofree char *rel = NULL;
  git_revwalk *walk = NULL;
  git_oid oid;
  GPtrArray *out;

  g_return_val_if_fail (vcs != NULL, NULL);
  g_return_val_if_fail (path != NULL, NULL);

  rel = rel_path (vcs, path);
  if (rel == NULL)
    {
      g_set_error (error, PASSFL_VCS_ERROR, PASSFL_VCS_ERROR_GIT,
                   "'%s' is outside the repository", path);
      return NULL;
    }

  out = g_ptr_array_new_with_free_func (vcs_commit_free);
  if (git_revwalk_new (&walk, vcs->repo) != 0 ||
      git_revwalk_push_head (walk) != 0)
    {
      /* unborn HEAD: an empty history, not an error */
      if (walk != NULL)
        git_revwalk_free (walk);
      return out;
    }
  git_revwalk_sorting (walk, GIT_SORT_TIME);

  while (git_revwalk_next (&oid, walk) == 0)
    {
      git_commit *commit = NULL;

      if (git_commit_lookup (&commit, vcs->repo, &oid) != 0)
        continue;
      if (commit_touches (vcs, commit, rel))
        {
          PassflVcsCommit *c = g_new0 (PassflVcsCommit, 1);
          char hex[GIT_OID_SHA1_HEXSIZE + 1] = { 0 };

          git_oid_fmt (hex, &oid);
          c->oid = g_strdup (hex);
          c->summary = g_strdup (git_commit_summary (commit));
          c->time = (gint64) git_commit_time (commit);
          g_ptr_array_add (out, c);
        }
      git_commit_free (commit);
    }
  git_revwalk_free (walk);
  return out;
}

GBytes *
passfl_vcs_file_at (PassflVcs *vcs, const char *oid_hex, const char *path,
                    GError **error)
{
  g_autofree char *rel = NULL;
  git_oid oid;
  git_commit *commit = NULL;
  git_tree *tree = NULL;
  git_tree_entry *entry = NULL;
  git_blob *blob = NULL;
  GBytes *bytes = NULL;

  g_return_val_if_fail (vcs != NULL, NULL);
  g_return_val_if_fail (oid_hex != NULL, NULL);
  g_return_val_if_fail (path != NULL, NULL);

  rel = rel_path (vcs, path);
  if (rel == NULL || git_oid_fromstr (&oid, oid_hex) != 0 ||
      git_commit_lookup (&commit, vcs->repo, &oid) != 0 ||
      git_commit_tree (&tree, commit) != 0)
    {
      set_git_error (error, "look up revision");
      goto out;
    }
  if (git_tree_entry_bypath (&entry, tree, rel) != 0)
    goto out; /* file absent in that revision — NULL, no error */
  if (git_blob_lookup (&blob, vcs->repo,
                       git_tree_entry_id (entry)) != 0)
    {
      set_git_error (error, "read blob");
      goto out;
    }
  bytes = g_bytes_new (git_blob_rawcontent (blob),
                       (gsize) git_blob_rawsize (blob));

out:
  if (blob != NULL)
    git_blob_free (blob);
  if (entry != NULL)
    git_tree_entry_free (entry);
  if (tree != NULL)
    git_tree_free (tree);
  if (commit != NULL)
    git_commit_free (commit);
  return bytes;
}

/* --- §6 message builders --------------------------------------------------- */

char *
passfl_vcs_msg_insert (const char *name)
{
  return g_strdup_printf ("Add given password for %s to store.", name);
}

char *
passfl_vcs_msg_edit (const char *name, gboolean existed)
{
  /* ${EDITOR:-vi} in pass; claiming vi would be false — SPEC §11.3. */
  return g_strdup_printf ("%s password for %s using Pass for Linux.",
                          existed ? "Edit" : "Add", name);
}

char *
passfl_vcs_msg_generate (const char *name, gboolean in_place)
{
  return g_strdup_printf ("%s generated password for %s.",
                          in_place ? "Replace" : "Add", name);
}

char *
passfl_vcs_msg_remove (const char *name)
{
  return g_strdup_printf ("Remove %s from store.", name);
}

/* --- multi-path commits (M4) ----------------------------------------------- */

const char *
passfl_vcs_workdir (PassflVcs *vcs)
{
  g_return_val_if_fail (vcs != NULL, NULL);
  return vcs->workdir;
}

gboolean
passfl_vcs_commit_paths (PassflVcs *vcs, const char *const *paths,
                         const char *message, GError **error)
{
  git_index *index = NULL;
  git_tree *tree = NULL;
  git_oid tree_oid, head_oid;
  gboolean ok = FALSE;

  g_return_val_if_fail (vcs != NULL, FALSE);
  g_return_val_if_fail (paths != NULL, FALSE);
  g_return_val_if_fail (message != NULL, FALSE);

  if (git_repository_index (&index, vcs->repo) != 0)
    {
      set_git_error (error, "open index");
      return FALSE;
    }

  for (guint i = 0; paths[i] != NULL; i++)
    {
      g_autofree char *rel = rel_path (vcs, paths[i]);

      if (rel == NULL)
        continue; /* outside this repository — pass ignores it too */
      if (*rel == '\0' || g_file_test (paths[i], G_FILE_TEST_IS_DIR))
        {
          char *specs[1] = { rel };
          git_strarray pathspec = { specs, *rel == '\0' ? 0 : 1 };

          if (git_index_add_all (index, &pathspec, 0, NULL, NULL) != 0 ||
              git_index_update_all (index, &pathspec, NULL, NULL) != 0)
            {
              set_git_error (error, "stage tree");
              goto out;
            }
        }
      else if (g_file_test (paths[i], G_FILE_TEST_EXISTS))
        {
          if (git_index_add_bypath (index, rel) != 0)
            {
              set_git_error (error, "stage file");
              goto out;
            }
        }
      else
        git_index_remove_bypath (index, rel); /* may be untracked — fine */
    }
  if (git_index_write (index) != 0 ||
      git_index_write_tree (&tree_oid, index) != 0)
    {
      set_git_error (error, "write index");
      goto out;
    }

  /* only-if-changed guard: same tree as HEAD means nothing to commit */
  if (git_reference_name_to_id (&head_oid, vcs->repo, "HEAD") == 0)
    {
      git_commit *head = NULL;
      gboolean same = FALSE;

      if (git_commit_lookup (&head, vcs->repo, &head_oid) == 0)
        {
          same = git_oid_equal (git_commit_tree_id (head), &tree_oid);
          git_commit_free (head);
        }
      if (same)
        {
          ok = TRUE;
          goto out;
        }
    }

  if (git_tree_lookup (&tree, vcs->repo, &tree_oid) != 0)
    {
      set_git_error (error, "write tree");
      goto out;
    }
  ok = commit_tree (vcs, tree, message, error);

out:
  if (tree != NULL)
    git_tree_free (tree);
  git_index_free (index);
  return ok;
}

/* --- M4 message builders ---------------------------------------------------- */

char *
passfl_vcs_msg_rename (const char *old_arg, const char *new_arg)
{
  return g_strdup_printf ("Rename %s to %s.", old_arg, new_arg);
}

char *
passfl_vcs_msg_copy (const char *old_arg, const char *new_arg)
{
  return g_strdup_printf ("Copy %s to %s.", old_arg, new_arg);
}

/* ${id_path:+ ($id_path)} */
static char *
subpath_tag (const char *subpath)
{
  if (subpath == NULL || *subpath == '\0')
    return g_strdup ("");
  return g_strdup_printf (" (%s)", subpath);
}

char *
passfl_vcs_msg_set_gpg_id (const char *ids_joined, const char *subpath)
{
  g_autofree char *tag = subpath_tag (subpath);

  return g_strdup_printf ("Set GPG id to %s%s.", ids_joined, tag);
}

char *
passfl_vcs_msg_deinit (const char *gpg_id_abs, const char *subpath)
{
  g_autofree char *tag = subpath_tag (subpath);

  /* pass puts the absolute .gpg-id path here (line 342) */
  return g_strdup_printf ("Deinitialize %s%s.", gpg_id_abs, tag);
}

char *
passfl_vcs_msg_reencrypt (const char *ids_joined, const char *subpath)
{
  g_autofree char *tag = subpath_tag (subpath);

  return g_strdup_printf ("Reencrypt password store using new GPG id %s%s.",
                          ids_joined, tag);
}

char *
passfl_vcs_msg_sign_gpg_id (const char *fprs_joined)
{
  return g_strdup_printf ("Signing new GPG id with %s.", fprs_joined);
}
