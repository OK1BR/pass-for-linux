# pass-for-linux

Native password manager for Linux (OK1BR). Fourth app of the family with
`sdr-for-linux`, `skimmer-for-linux` and `log-for-linux` — same conventions apply:

- Plain **C11**, GTK4 + libadwaita, meson. No Rust/Python in the app.
- **Engine is GLib-only** (`src/engine/`, no GTK includes) — headless and
  testable; the GTK front-end lives in `src/app/`.
- App id: `cz.ok1br.pass_for_linux`. License: GPL-3.0-or-later.
- Build: `meson setup builddir && meson compile -C builddir`.
- On Arch always build from source; install goes to `~/.local`, not `/usr`.

Scope/design: `docs/SPEC.md` (written 2026-07-28 — **read it first**; it is a
specification of `pass` behaviour derived from the script itself, with line
references, plus the decided architecture and milestones).

**Status: M2 done** — writes work end to end: `crypto.c` encrypts with
the §3 flags via GPGME + atomic replace, `generate.c` rejection-samples
from getrandom, `store.c` write/delete with umask modes and `rmdir -p`
pruning, §2.4 signed `.gpg-id` fully verified (settles SPEC §11.1).
UI: editor (`entry-edit.c`), new/delete with confirms, §4.5 overwrite
and §7.7 mtime guards, live sidebar via GFileMonitor. Conformance rig
(`conformance_test.c`) compares engine vs real `pass` on identical
stores — trees, modes, content, OpenPGP packets. 6/6 gates green.
Note: PASSWORD_STORE_GPG_OPTS cannot pass through GPGME — writes refuse
loudly when it is set. Next: M3 (libgit2 — commit per operation, §6
messages, per-entry history).

## Four rules that override convenience

1. **Compatibility with `pass` 1.7.4 is the point of this app.** Anything written
   must be readable by the CLI — including git commit messages (SPEC §6). When in
   doubt, the script `/usr/bin/pass` wins over the spec, and the spec wins over
   what seems reasonable.
2. **No subprocesses.** Never spawn `pass`, `gpg` or `git`. Crypto is GPGME, VCS
   is libgit2, passphrases are gpg-agent's business (never our own dialog).
3. **Nothing decrypted ever reaches persistent storage.** Editing happens in
   memory, in `gcry_malloc_secure()` buffers. Not even a temp file in `/dev/shm`.
4. **The user's real store is not a test fixture.** `~/.password-store` holds
   Richard's actual passwords. Tests run against throwaway stores under
   `$PASSWORD_STORE_DIR` pointed at a temp directory — never the default path.
