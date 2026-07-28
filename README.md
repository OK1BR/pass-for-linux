# Pass for Linux

**A native GTK4/libadwaita password manager for Linux.** The fourth app in the
family around [`sdr-for-linux`](https://github.com/OK1BR/sdr-for-linux),
[`skimmer-for-linux`](https://github.com/OK1BR/skimmer-for-linux) and
[`log-for-linux`](https://github.com/OK1BR/log-for-linux), sharing their
technology and architecture: a headless, GLib-only engine under a
GTK4/libadwaita front-end, plain C11, meson.

It is a front-end for the [`pass`](https://www.passwordstore.org/) password
store — the same directory of GPG-encrypted files, read and written in place.
`pass` on the command line and this app can be used on one store
interchangeably; neither needs to know about the other.

> **Status:** M3 — git works. Every write commits through libgit2 with
> `pass`-compatible messages (§6), signed when `pass.signcommits` says so;
> per-entry history shows native plaintext diffs of old revisions and can
> restore one. Plus everything from M2: atomic umask-correct writes,
> `--compress-algo=none` / `--no-encrypt-to` via GPGME, signed `.gpg-id`,
> all conformance-tested against `pass` 1.7.4.
> Read [`docs/SPEC.md`](docs/SPEC.md).

## Why

`pass` is a 720-line bash script whose best property is that it has no format of
its own: entries are `*.gpg` files in a directory tree, recipients live in
`.gpg-id`, history is plain git. That survives its own tooling. What it lacks is
a graphical client that is actually native — the existing ones are a Rust TUI, Qt,
or web pages in an Electron wrapper.

Nothing here reimplements GnuPG. Crypto goes through **GPGME**, git through
**libgit2**, passphrases through **gpg-agent** and its pinentry — all C
libraries, all already packaged.

## Design rules

1. Anything written here must be readable by `pass` 1.7.4 — including the git
   commit messages.
2. No subprocesses: never spawn `pass`, `gpg` or `git`.
3. Nothing decrypted ever reaches persistent storage.
4. No network except git remotes the user configured. No telemetry, no account.

## Licence

GPL-3.0-or-later. Richard Fakenberg, OK1BR.
