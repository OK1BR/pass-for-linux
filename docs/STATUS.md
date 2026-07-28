# Status and handover — 2026-07-28

Where the project stands after the first implementation session, what is
deliberately absent, and how to pick it back up. `docs/SPEC.md` stays the
authority on *what* the app must do; this file records *how far it got*.

## In one line

M0–M5 of the SPEC §10 plan are implemented and conformance-tested against
`pass` 1.7.4 and pass-otp 1.2.0; 9 test gates pass; M6 (packaging) is
**postponed at Richard's request** — the app is being manually tested over
his real store instead.

## Milestones

| | Gate | State |
|---|---|---|
| M0 | Tree scan, `.gpg-id` resolution | done |
| M1 | GPGME decrypt, read-only viewer | done |
| M2 | insert / edit / generate / rm, atomic + umask-correct | done |
| M3 | git via libgit2, §6 messages, history + diffs | done |
| M4 | mv / cp with §4.10 re-encryption, init/deinit, recipient view | done |
| M5 | TOTP/HOTP, native HMAC codes, countdown UI | done |
| M6 | Packaging: PKGBUILD, metainfo, icon, `.desktop`, CI | **not started (deliberate)** |

## Layout

```
src/engine/     GLib only, no GTK — headless and testable
  store.c       scan, entry paths, write/delete, §4.10 re-encryption,
                mv/cp, init/deinit, GFileMonitor watch
  recipients.c  .gpg-id resolution (§2.2), gpg group expansion (§4.9)
  crypto.c      GPGME decrypt/encrypt, secure buffers, atomic replace,
                PKESK key IDs, .gpg-id signing and verification (§2.4)
  entry.c       line-1 password + metadata, verbatim round-trip
  generate.c    tr-set expansion, rejection sampling from getrandom (§4.8)
  vcs.c         libgit2: discovery, commits, signing, history, §6 messages
  otp.c         otpauth:// parsing, base32, RFC 4226 HMAC codes
src/app/        GTK4 / libadwaita
  window.c      split view, tree, search, decrypt flow, all actions
  entry-view.c  reveal, copy with clear timer, live TOTP rows
  entry-edit.c  structured editor, generator, strength meter
  history.c     per-entry git history, plaintext line diff, restore
  recipient-view.c  who a subtree encrypts to + re-encrypt
src/*_test.c    one gate per topic, run by `meson test -C builddir`
```

## Test gates (`meson test -C builddir`)

`store`, `recipients`, `entry`, `crypto`, `generate`, `conformance`,
`vcs`, `m4`, `otp` — 9 suites. The last four are **conformance rigs**: they
drive the same operation through our engine on store A and through the
real `pass` / `pass otp` on store B and compare trees, file modes,
decrypted content, OpenPGP packet shapes, PKESK key IDs and
`git log --format=%s`. `otp` additionally checks the full RFC 6238
Appendix B and RFC 4226 Appendix D vector tables.

Spawning `pass`/`gpg`/`git` **inside tests** is the conformance method and
is fine; the app itself must never do it (rule 2). Every test builds
throwaway stores and a throwaway `GNUPGHOME` under `$TMPDIR` and masks
git's global config (`GIT_CONFIG_GLOBAL=/dev/null`,
`GIT_CONFIG_NOSYSTEM=1`) — note libgit2 ignores those, so fixture repos
also set `commit.gpgsign=false` and `pass.signcommits=false` locally.

## How the UI was verified

There is no automated UI test. Each milestone was checked by temporarily
adding, to `main.c`, a `SIGUSR1` handler that renders the window to a PNG
via `gtk_widget_paintable_new` + `gsk_renderer_render_texture`, plus a
`PASSFL_AUTODRIVE` timer chain in `window.c` that activates the actions
under test. The app then runs on the real Wayland session against a
fixture store, screenshots are read back, and **all of that scaffolding is
stripped before committing** (grep for `TEMP`, `AUTODRIVE`, `SIGUSR1`,
`passfl-temp` — the tree must come back clean). `PASSFL_AUTOCLOSE_MS`
survives in `main.c` as the one permanent repro hook.

Broadway (`gtk4-broadwayd` + a browser tab) was tried first and is a dead
end: a backgrounded tab stops the frame clock, so snapshots come back
empty. Use the real session.

## Decisions settled during implementation (SPEC §11)

1. **§11.1 signed `.gpg-id`** — implemented in full, not skipped:
   verification runs exactly where pass's `verify_file` does, and `init`
   signs when `PASSWORD_STORE_SIGNING_KEY` is set.
2. **§11.3 editor name** — the edit commit says `using Pass for Linux.`
   Claiming `vi` would be false. This is the one intentional deviation
   from the §6 message table; the `vcs` gate asserts it explicitly.
3. **§11.4 metadata editor** — deliberately unopinionated: every line
   after the password is edited verbatim in its own row, so files that
   ignore the `key: value` convention round-trip untouched.
4. **§11.2 `grep`** — still open, and **not implemented**. Full-store
   decryption remains a CLI-only capability for now.

## Known limits and non-features

- **`PASSWORD_STORE_GPG_OPTS`**: GPGME cannot forward arbitrary gpg CLI
  options, so writes **refuse loudly** when it is set rather than
  silently producing something else than `pass` would. Reads are fine.
- **`pass grep`**, QR codes, `generate --in-place` as a distinct UI
  action, recursive delete of a directory, and mv/cp of whole
  directories from the UI are not exposed. The engine's mv/cp *does*
  handle directories; only the UI is entry-only.
- Non-goals from the spec stand: no browser integration, no import from
  other managers, no multi-store switching, no SSH agent.
- The clipboard restore-after-timeout path is implemented and its logic
  is unit-visible, but **the end-to-end effect was never observed in a
  headless run** (the compositor refuses clipboard ownership to an
  unfocused window). It needs one human confirmation in normal use.

## Environment notes

- Richard's real store `~/.password-store` is currently **empty** — only
  `.gpg-id` with key `35AE58A87CFC4FAEAB754E5A6A5918E1EDB33931`
  (`Richard Fakenberg <rifak@protonmail.com>`) and it is **not** a git
  repository, so history/restore features are inert there until he runs
  `pass git init` himself. A tarball backup was taken to
  `~/pass-store-zaloha-20260728.tar.gz`.
- Repo: <https://github.com/OK1BR/pass-for-linux>, public, branch `main`.
- Build: `meson setup builddir && meson compile -C builddir`;
  run `./builddir/pass-for-linux`.

## Picking it back up

Richard is testing the app manually. Expect small UI corrections (the
first one — double-click on a folder toggling its subtree — is already
in). Start from whatever he reports; **do not start M6 packaging unless
he asks for it**.
