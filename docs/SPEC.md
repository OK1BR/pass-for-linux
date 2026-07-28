# Pass for Linux — specification

Goal: a native Linux **password manager** — the fourth app of the family around
**[`sdr-for-linux`](https://github.com/OK1BR/sdr-for-linux)**,
**[`skimmer-for-linux`](https://github.com/OK1BR/skimmer-for-linux)** and
**[`log-for-linux`](https://github.com/OK1BR/log-for-linux)**, sharing their stack
and architecture: a headless, **GLib-only engine** (`src/engine/`, no GTK
includes) under a GTK4/libadwaita front-end, plain C11, meson.

Author: Richard Fakenberg, **OK1BR**. Licence: GPL-3.0-or-later.

The app is a **native front-end for the `pass` password store**. It does not
invent a format, does not wrap the `pass` shell script, and does not own the
data. It reads and writes the same directory `pass(1)` does, so both can be used
on the same store, interchangeably, without either knowing about the other.

## Why this exists

`pass` is a 720-line bash script (`/usr/bin/pass`, v1.7.4, Jason A. Donenfeld)
that shells out to `gpg` (31 call sites) and `git` (25). Its data model is not a
database but a convention: a directory of GPG-encrypted files. That convention is
its best property — auditable, greppable, backup-friendly, survivable if every
tool around it disappears.

What is missing is a graphical client that respects it. The existing options are
a Rust TUI (`ripasso`), Qt (`QtPass`), or Electron-shaped apps that are web pages
in a wrapper. There is no native GTK4/libadwaita client, and none of the GUI
options are written against the same stack as the rest of this family.

Because the format is this simple, a C client does not need to reimplement much:
GnuPG already ships **GPGME**, a C API, and git ships **libgit2**. The heavy
lifting — key handling, agent communication, pinentry — is delegated to software
that already does it correctly.

## Non-goals

- **No new format.** Anything this app writes must be readable by `pass` 1.7.4.
- **No sync service, no cloud, no account.** Sync is git, or nothing.
- **No browser integration in v1.** Native messaging hosts and autofill are a
  separate problem with a separate threat model.
- **No reimplementation of GnuPG.** Crypto goes through GPGME/gpg-agent.
- **Not a `pass` wrapper.** The app must never spawn `pass`, `gpg` or `git` as
  subprocesses. Everything is in-process via libraries.

---

# 1. Compatibility contract

This is the hard requirement the whole project hangs on:

> Any store written by Pass for Linux MUST be operable by `pass` 1.7.4 with no
> conversion step, and any store written by `pass` MUST be operable by Pass for
> Linux.

That includes the git history: commit messages are part of the observable
behaviour and MUST match (§6), because a store is frequently shared between the
CLI and the GUI and a mixed history should read as if one tool produced it.

Conformance is measured by a test suite that runs the same operation through both
implementations on identical stores and compares the resulting tree, file
permissions, decrypted content and `git log --format=%s`.

---

# 2. Store format (normative)

All statements in this section were verified against `/usr/bin/pass` v1.7.4;
line references are to that file.

## 2.1 Layout

```
$PASSWORD_STORE_DIR (default ~/.password-store)
├── .gpg-id                      # recipient list for this subtree
├── .gpg-id.sig                  # optional detached signature (§2.4)
├── .gitattributes               # written by `git init` (§6)
├── .extensions/                 # user extensions (opt-in, §7.5)
├── social/
│   ├── .gpg-id                  # optional override for this subtree
│   └── github.gpg               # entry "social/github"
└── bank.gpg                     # entry "bank"
```

- An **entry name** is its path relative to the store root, without the `.gpg`
  suffix. Directory separators are literal `/`.
- Entry files are GPG-encrypted, one per entry. Nothing else in the tree is
  encrypted — **names, directory structure and file sizes are cleartext.** This
  is a known and accepted property of the format, not a defect to be fixed
  unilaterally; changing it would break §1.
- Symlinked entries MUST be skipped during re-encryption (`[[ -L $passfile ]] &&
  continue`, line 114) but MAY be shown read-only in the UI.

## 2.2 Recipient resolution (`.gpg-id`)

The single most error-prone part of the format. Verified at lines 70–108.

1. If the environment variable `PASSWORD_STORE_KEY` is set, its whitespace-separated
   values are the recipients. **Nothing else is consulted** — no file lookup at all.
2. Otherwise, start at the directory containing the entry and walk **upwards**,
   testing `<dir>/.gpg-id` at each step, stopping when the store root is reached.
   The first `.gpg-id` found wins. A nested `.gpg-id` therefore fully overrides
   its ancestors for that subtree — it does not merge with them.
3. If the walk reaches the root and `$PASSWORD_STORE_DIR/.gpg-id` does not exist,
   the store is uninitialised: fail with the "You must run: pass init your-gpg-id"
   error rather than encrypting to a guessed key.

`.gpg-id` parsing (lines 102–107): one recipient per line; everything from the
first `#` to end of line is stripped as a comment; empty lines after stripping are
skipped. A recipient may be any string `gpg` accepts with `-r` — key ID,
fingerprint, e-mail, or a **gpg group name** (§4.9).

## 2.3 Entry content

There is **no schema**. An entry is arbitrary UTF-8 text. Two conventions, both
of which the app MUST follow and MUST NOT enforce on read:

- **Line 1 is the password.** `--clip`/`--qrcode` default to line 1 and select
  line N via `tail -n +N | head -n 1` (lines 373–374, 390). Line numbering is
  1-based.
- **Remaining lines are free-form metadata.** The de-facto community convention is
  `key: value`, commonly `url:`, `user:`, `login:`. The app SHOULD offer a
  structured editor over these, MUST round-trip unknown lines untouched, and MUST
  preserve line order.

**TOTP** (`pass-otp` compatibility, verified in
`/usr/lib/password-store/extensions/otp.bash`): a line whose content is an
`otpauth://totp/…` or `otpauth://hotp/…` URI. Query parameters: `secret`
(required, base32), `digits`, `algorithm`, `period`, `counter` (required for
hotp). Defaults when absent: SHA1, period 30, 6 digits. The app SHOULD compute
codes natively via libgcrypt HMAC rather than depending on `oathtool`.

## 2.4 Signed `.gpg-id`

If `PASSWORD_STORE_SIGNING_KEY` is set (lines 59–69), a detached signature
`<file>.sig` MUST exist next to `.gpg-id` and MUST verify against at least one of
the whitespace-separated 40-hex-character fingerprints in that variable. Anything
else — missing signature, non-matching signer, malformed fingerprint — is a hard
failure, not a warning. The same check applies to user extensions (line 685).

## 2.5 Path safety

Any path component equal to `..` MUST be rejected before use (line 145). This is
a guard against an entry name escaping the store root, and the app MUST apply it
to every user-supplied name, including drag-and-drop and import paths.

---

# 3. GPG parameters

`pass` invokes gpg with a fixed option set (line 9):

```
--quiet --yes --compress-algo=none --no-encrypt-to
```

Two of these are semantically visible and MUST be reproduced through GPGME:

- **`--compress-algo=none`** — no compression before encryption. Beyond
  determinism, compressing attacker-influenced plaintext alongside secrets is the
  shape of a compression-oracle problem; keep it off.
- **`--no-encrypt-to`** — ignore any `encrypt-to`/`default-recipient` in the
  user's `gpg.conf`. Without it, a store could silently gain a recipient that is
  not in `.gpg-id`, which the UI would then not display. This is a security
  property, not a cosmetic flag.

`$PASSWORD_STORE_GPG_OPTS` is prepended and MUST be honoured.

Passphrase entry is delegated to **gpg-agent**, which selects pinentry itself.
The app MUST NOT implement its own passphrase dialog, must not set a GPGME
passphrase callback, and must never hold the key passphrase in its own memory.
On a Wayland GNOME session `/usr/bin/pinentry` resolves to `pinentry-gnome3`,
so this yields a native dialog with no work on our side.

---

# 4. Operations

Each operation lists the observable effects. All of them MUST leave the store in
the state `pass` would have produced.

| # | Operation | Semantics |
|---|---|---|
| 4.1 | **list** | Tree of entry names with `.gpg` stripped. Root label is `Password Store`. |
| 4.2 | **show** | Decrypt whole entry. Selecting line N for clip/QR is 1-based; if line N is empty → `There is no password to put on the clipboard at line N.` |
| 4.3 | **find** | Case-insensitive glob over entry *names*. No decryption. |
| 4.4 | **grep** | Decrypts **every** entry in the store and searches the plaintext. Expensive and passphrase-gated; the UI MUST show progress and MUST be cancellable. |
| 4.5 | **insert** | Create/overwrite one entry; prompt before overwrite unless forced. |
| 4.6 | **edit** | Decrypt → edit → re-encrypt. If the new content is byte-identical, do nothing and report `Password unchanged.` (line 504) — no commit, no rewrite. |
| 4.7 | **generate** | §4.8. `--in-place` replaces **only line 1** and keeps the rest of the file (line 544). |
| 4.8 | **rm** | Delete entry (or subtree). After deletion, prune now-empty parent directories up to the store root (`rmdir -p`, line 593). |
| 4.9 | **mv / cp** | Move/copy, then **re-encrypt the destination** to whatever `.gpg-id` applies there (§4.10). Crossing a subtree boundary with a different key MUST re-encrypt. |
| 4.10 | **init** | Write `.gpg-id`, then re-encrypt the affected subtree (§4.10). `init` with an empty argument *removes* `.gpg-id` and de-initialises the subtree (lines 337–344). |

## 4.8 Password generation

Verified at lines 19–21 and 538.

- Default length **25**, overridable by `$PASSWORD_STORE_GENERATED_LENGTH`.
- Default alphabet is the POSIX classes `[:punct:][:alnum:]` in the **C locale**;
  `--no-symbols` narrows it to `[:alnum:]`. Both are overridable by
  `$PASSWORD_STORE_CHARACTER_SET` / `…_NO_SYMBOLS`.
- Source is `/dev/urandom`, filtered by rejection (`tr -dc`). The C
  implementation MUST use rejection sampling from `getrandom(2)`, never modulo
  reduction over a byte, or the distribution is skewed toward the low end of the
  alphabet.

## 4.10 Re-encryption

The algorithm (lines 110–141) is not "decrypt everything and write it back" — it
is a diff, and doing it eagerly would be both slow and needlessly exposing:

1. Walk `*.gpg` under the target path, skipping symlinks and `.git`.
2. Resolve recipients for each file's directory (§2.2) and expand any **gpg
   groups** via `--list-config group`.
3. Compute the set of **encryption-capable subkeys** of those recipients.
4. Read the set of key IDs the file is *currently* encrypted to.
5. **Only if the two sets differ**, decrypt and re-encrypt via a temporary file
   in the same directory, then rename over the original.

The temporary file MUST be created with the store umask and MUST be unlinked if
encryption fails (line 137).

---

# 5. Environment variables

All of these MUST be honoured; several change where data lands, so ignoring one
is a correctness bug, not a missing feature.

| Variable | Default | Effect |
|---|---|---|
| `PASSWORD_STORE_DIR` | `~/.password-store` | Store root |
| `PASSWORD_STORE_KEY` | — | Overrides `.gpg-id` lookup entirely (§2.2) |
| `PASSWORD_STORE_GPG_OPTS` | — | Extra gpg options |
| `PASSWORD_STORE_UMASK` | `077` | umask for everything written (line 6) |
| `PASSWORD_STORE_CLIP_TIME` | `45` | Clipboard clear delay, seconds |
| `PASSWORD_STORE_X_SELECTION` | `clipboard` | `clipboard` or `primary` |
| `PASSWORD_STORE_GENERATED_LENGTH` | `25` | Default generated length |
| `PASSWORD_STORE_CHARACTER_SET` | `[:punct:][:alnum:]` | Generator alphabet |
| `PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS` | `[:alnum:]` | Alphabet, no symbols |
| `PASSWORD_STORE_SIGNING_KEY` | — | Fingerprints for `.gpg-id` verification (§2.4) |
| `PASSWORD_STORE_ENABLE_EXTENSIONS` | — | `true` enables **user** extensions only |
| `PASSWORD_STORE_EXTENSIONS_DIR` | `$PREFIX/.extensions` | User extension directory |

Note the asymmetry at lines 678–683: **system** extensions in
`/usr/lib/password-store/extensions` are always active; the opt-in variable gates
only the per-store ones. This is why `pass otp` works with no configuration.

---

# 6. Git integration

The store may be a git repository rooted at the store root **or at any directory
between the entry and the root** (`set_git`, lines 30–36) — the app must discover
the repository by walking up from the touched file, not by assuming the root.
`GIT_CEILING_DIRECTORIES` is set to the store's parent (line 24) so discovery
never escapes upward; libgit2's `git_repository_open_ext` with a ceiling
directory reproduces this.

Every mutating operation is committed immediately, one commit per operation, and
only if the file actually changed (`git status --porcelain` guard, line 40). If
`git config --bool pass.signcommits` is true, commits are GPG-signed (line 46).

Commit messages are part of the compatibility contract:

| Operation | Message |
|---|---|
| `init` | `Set GPG id to <ids>[ (<subpath>)].` |
| `init ""` | `Deinitialize <path>[ (<subpath>)].` |
| after `init` | `Reencrypt password store using new GPG id <ids>[ (<subpath>)].` |
| signed `.gpg-id` | `Signing new GPG id with <fingerprints>.` |
| `insert` | `Add given password for <path> to store.` |
| `edit` | `Add password for <path> using <editor>.` / `Edit password for …` |
| `generate` | `Add generated password for <path>.` / `Replace generated password for …` |
| `rm` | `Remove <path> from store.` |
| `mv` | `Rename <old> to <new>.` + `Remove <old>.` |
| `cp` | `Copy <old> to <new>.` |
| `git init` | `Add current contents of password store.` |
| `git init` | `Configure git repository for gpg file diff.` |

`git init` additionally writes `.gitattributes` containing `*.gpg diff=gpg` and
sets the local config `diff.gpg.binary=true` and
`diff.gpg.textconv=gpg -d <opts>` (lines 658–661), which is what makes
`git diff` show plaintext diffs of encrypted entries.

For the editor's own use, `<editor>` in the commit message is the name of the
editor actually used; Pass for Linux SHOULD write `Pass for Linux` there rather
than a shell editor name, since claiming `vi` would be false.

---

# 7. Security requirements

1. **Plaintext never touches persistent storage.** `pass` decrypts to a temp file
   only for `edit`, and only inside `/dev/shm`, falling back to `$TMPDIR` with a
   `shred` on exit (lines 216–244). This app has no such excuse: editing happens
   in memory. Nothing decrypted is ever written to disk.
2. **Secret memory.** Decrypted buffers MUST be allocated with
   `gcry_malloc_secure()` (mlocked, wiped on free) where the data crosses our
   own code. GPGME's own buffers are not secure memory — copy out and wipe the
   GPGME buffer explicitly rather than assuming it is handled.
3. **umask 077 on every write**, including temporary files and the git objects
   created through libgit2.
4. **Clipboard** must self-clear after `$PASSWORD_STORE_CLIP_TIME`, restore the
   previous clipboard content, and survive the app being closed in the meantime.
   Under GTK4 this is `GdkClipboard`; note that Wayland clipboard ownership dies
   with the process, so the clear timer MUST NOT be the only mechanism — losing
   ownership must also be handled.
5. **Extensions are code execution.** `pass` extensions are bash sourced into the
   shell (line 693). This app MUST NOT execute them. It MAY list them as
   "CLI-only features present in this store" for the user's information.
6. **No telemetry, no network.** The only network access in the entire app is
   git remote traffic through libgit2, and only when the user asks for it.
7. **Locking.** Concurrent access from the CLI is expected and normal. Writes MUST
   be atomic (temp file + `rename(2)` in the same directory) and the app MUST
   detect on-disk changes and reload rather than overwrite blindly.

---

# 8. Architecture

Same split as the rest of the family: a headless engine with no GTK includes,
and a front-end that owns no logic.

```
src/
├── engine/                 # GLib only — no GTK, unit-testable, no UI strings
│   ├── store.c             # tree scan, entry names, watch via GFileMonitor
│   ├── recipients.c        # .gpg-id resolution, groups, signature check
│   ├── crypto.c            # GPGME wrapper, secure buffers
│   ├── entry.c             # line-1 password + metadata parsing, round-trip
│   ├── otp.c               # otpauth:// parse, TOTP/HOTP via libgcrypt
│   ├── generate.c          # rejection sampling from getrandom()
│   └── vcs.c               # libgit2, commit messages per §6
└── app/                    # GTK4 / libadwaita front-end (family convention)
    ├── window.c            # AdwNavigationSplitView: tree | entry
    ├── entry-view.c        # reveal, copy, TOTP countdown
    ├── entry-edit.c        # structured metadata editor
    └── history.c           # git log of one entry
```

Dependencies, all already in Arch's official repositories:

| Library | Arch package | Role |
|---|---|---|
| GPGME | `core/gpgme` | GnuPG C API, agent/pinentry delegation |
| libgit2 | `extra/libgit2` | Repository discovery, commits, history |
| libgcrypt | `core/libgcrypt` | Secure memory, HMAC for TOTP |
| GTK4 + libadwaita | `extra/gtk4`, `extra/libadwaita` | Front-end |

Build: meson, C11, `cz.ok1br.pass_for_linux` as the application ID.

The engine MUST be usable without the UI — that keeps the conformance test suite
(§1) honest and leaves the door open to a small CLI later without restructuring.

---

# 9. UI scope for v1

What a GUI can add over the CLI without breaking §1:

- Tree of the store in a sidebar; type-ahead filters by name (no decryption).
- Entry view: password hidden by default, one-click copy with the clear timer
  visible, metadata rendered as rows, `otpauth://` shown as a live TOTP code with
  a countdown ring.
- Entry editor: password field with strength meter and a generator, metadata rows
  added/removed as widgets; unknown lines preserved verbatim.
- Per-entry history from git, with plaintext diffs (§6), and restore of an older
  revision.
- Recipient view: which keys a subtree is encrypted to, sourced from `.gpg-id`,
  with a warning when the resolved key set differs from what the files actually
  carry (§4.10 step 4/5 — this is the state `pass init` would fix).

Explicitly **not** in v1: browser integration, import/export from other managers,
multi-store switching, SSH agent.

---

# 10. Milestones

| | Gate |
|---|---|
| **M0** | Engine reads a store: tree scan, `.gpg-id` resolution incl. nested override, no crypto yet. Unit tests against fixture stores. |
| **M1** | Decrypt via GPGME with agent-driven pinentry; read-only UI (tree + entry view + copy with timer). Usable as a viewer. |
| **M2** | Writes: insert, edit, generate, rm — atomic, umask-correct, conformance-tested against `pass` 1.7.4. |
| **M3** | git via libgit2: commit per operation with §6 messages, per-entry history, plaintext diff. |
| **M4** | mv/cp with re-encryption; `init`; recipient view and the "needs re-encryption" warning. |
| **M5** | TOTP: `otpauth://` parsing, native HMAC codes, countdown UI, `pass-otp`-compatible writes. |
| **M6** | Packaging: PKGBUILD, appstream metainfo, icon, `.desktop`; conformance suite in CI. |

---

# 11. Open decisions

1. **`.gpg-id` signing (§2.4)** — implement in v1, or fail loudly when
   `PASSWORD_STORE_SIGNING_KEY` is set and refuse to open? Failing loudly is
   safer than silently skipping a verification the user asked for.
2. **`grep` (§4.4)** — full-store decryption is a real capability but also the
   single most dangerous operation in the app. Offer it, or leave it to the CLI?
3. **Editor commit message (§6)** — deviating from `pass` here is a deliberate,
   documented break of the message table. Confirm this is wanted.
4. **Entry metadata editor** — how opinionated should the `key: value` parsing be
   for files that do not follow the convention at all?

---

## Appendix: verification

Every normative claim above was read out of the actual installed sources rather
than from documentation:

- `/usr/bin/pass` — pass 1.7.4-3 (Arch `extra/pass`), 720 lines, `#!/usr/bin/env bash`,
  GPLv2+, Jason A. Donenfeld.
- `/usr/lib/password-store/extensions/otp.bash` — pass-otp 1.2.0-3, 426 lines.

Where this document says MUST, it is describing behaviour observed in those
files at the cited line numbers. `pass` has no formal specification; this
document is an attempt at one, and any disagreement between it and the script
should be resolved in favour of the script.
