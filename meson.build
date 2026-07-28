project('pass-for-linux', 'c',
  version : '0.0.0',
  license : 'GPL-3.0-or-later',
  default_options : [
    'c_std=c11',
    'warning_level=2',
    'buildtype=debugoptimized',
  ],
)

add_project_arguments('-D_GNU_SOURCE', language : 'c')
add_project_arguments('-DPASSFL_VERSION="@0@"'.format(meson.project_version()),
                      language : 'c')

# --- Dependencies -----------------------------------------------------------
# Same split as the rest of the family: the store engine is GLib-only
# (headless, testable), the app adds GTK4/libadwaita on top.
glib_dep   = dependency('glib-2.0')
gio_dep    = dependency('gio-2.0')          # store watch via GFileMonitor
gpgme_dep  = dependency('gpgme')            # M1: decrypt, agent pinentry
gcrypt_dep = dependency('libgcrypt')        # M1: secure buffers; M5: TOTP HMAC
gtk_dep    = dependency('gtk4')             # M1: front-end
adw_dep    = dependency('libadwaita-1')     # M1: front-end
git2_dep   = dependency('libgit2')          # M3: commit per op, history

engine_inc = include_directories('src/engine')

# --- Engine (headless, GLib-only) -------------------------------------------
# Grows milestone by milestone (docs/SPEC.md §10). M0: read a store — tree
# scan and .gpg-id recipient resolution, no crypto yet.
engine_sources = [
  'src/engine/store.c',        # M0: tree scan, entry names, path safety
  'src/engine/recipients.c',   # M0: .gpg-id resolution (SPEC §2.2)
  'src/engine/crypto.c',       # M1: GPGME decrypt, secure buffers (§3, §7)
  'src/engine/entry.c',        # M1: line-1 password + metadata (§2.3)
  'src/engine/generate.c',     # M2: rejection sampling from getrandom (§4.8)
  'src/engine/vcs.c',          # M3: libgit2, commit messages per §6
]
engine_deps = [glib_dep, gio_dep, gpgme_dep, gcrypt_dep, git2_dep]

engine_lib = static_library('passfl-engine',
  engine_sources,
  include_directories : engine_inc,
  dependencies : engine_deps,
)

# --- Gates (offline tests, family house style) -------------------------------
# All tests build their own throwaway fixture stores in a temp directory.
# The user's real ~/.password-store is never touched (CLAUDE.md rule 4).

# M0: tree scan — entries, nesting, symlinks, hidden files, sneaky paths.
pass_store_test = executable('pass-store-test',
  ['src/store_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('store', pass_store_test, timeout : 30)

# M0: .gpg-id resolution — walk-up, nested override, PASSWORD_STORE_KEY,
# uninitialised store, comment/blank parsing.
pass_recipients_test = executable('pass-recipients-test',
  ['src/recipients_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('recipients', pass_recipients_test, timeout : 30)

# M1: entry parsing — lines, kv hints, secure-memory placement.
pass_entry_test = executable('pass-entry-test',
  ['src/entry_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('entry', pass_entry_test, timeout : 30)

# M1: GPGME decrypt round-trip in a throwaway GNUPGHOME (spawns gpg to
# build the fixture — conformance method of SPEC §1; the app never does).
pass_crypto_test = executable('pass-crypto-test',
  ['src/crypto_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('crypto', pass_crypto_test, timeout : 60)

# M2: generation — tr-set expansion, lengths, alphabet membership.
pass_generate_test = executable('pass-generate-test',
  ['src/generate_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('generate', pass_generate_test, timeout : 30)

# M2: the SPEC §1 rig — engine on store A, real pass on store B, compare
# trees, modes, decrypted content and OpenPGP packet shapes.
pass_conformance_test = executable('pass-conformance-test',
  ['src/conformance_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('conformance', pass_conformance_test, timeout : 120)

# M3: git — §6 messages vs real pass on identical repos, signcommits
# verified by real `git verify-commit`, history and revision reads.
pass_vcs_test = executable('pass-vcs-test',
  ['src/vcs_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('vcs', pass_vcs_test, timeout : 120)

# M4: mv/cp/init/re-encryption vs real pass — messages, PKESK key IDs,
# untouched-bytes checks, groups, signed init, deinit quirks.
pass_m4_test = executable('pass-m4-test',
  ['src/m4_test.c'],
  include_directories : engine_inc,
  dependencies : engine_deps,
  link_with : engine_lib,
)
test('m4', pass_m4_test, timeout : 120)

# --- App --------------------------------------------------------------------
m_dep = meson.get_compiler('c').find_library('m', required : false)

executable('pass-for-linux',
  [
    'src/app/main.c',        # M1: AdwApplication bootstrap
    'src/app/window.c',      # M1: split view, store tree, decrypt flow
    'src/app/entry-view.c',  # M1: reveal, copy with the clear timer
    'src/app/entry-edit.c',  # M2: structured editor, generator, strength
    'src/app/history.c',     # M3: per-entry history, plaintext diff, restore
    'src/app/recipient-view.c', # M4: recipients + needs-reencryption
  ],
  include_directories : engine_inc,
  dependencies : [glib_dep, gio_dep, gpgme_dep, gcrypt_dep, gtk_dep, adw_dep,
                  git2_dep, m_dep],
  link_with : engine_lib,
  install : true,
)
