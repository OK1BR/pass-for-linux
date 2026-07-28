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
glib_dep = dependency('glib-2.0')
gio_dep  = dependency('gio-2.0')      # M1: store watch via GFileMonitor
# M1: dependency('gpgme')             — decrypt, agent-driven pinentry
# M2: dependency('libgcrypt')         — secure buffers, later TOTP HMAC (M5)
# M3: dependency('libgit2')           — commit per operation, history
# M1: dependency('gtk4'), dependency('libadwaita-1') — front-end

engine_inc = include_directories('src/engine')

# --- Engine (headless, GLib-only) -------------------------------------------
# Grows milestone by milestone (docs/SPEC.md §10). M0: read a store — tree
# scan and .gpg-id recipient resolution, no crypto yet.
engine_sources = [
  'src/engine/store.c',        # M0: tree scan, entry names, path safety
  'src/engine/recipients.c',   # M0: .gpg-id resolution (SPEC §2.2)
]
engine_deps = [glib_dep, gio_dep]

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
