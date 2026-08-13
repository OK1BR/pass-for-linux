# Desktop integration, icon slice only (2026-08-13): the About dialog's
# application_icon resolves through the icon theme, so the SVG must be
# installed — a builddir-run app finds it in ~/.local/share/icons too.
# The .desktop launcher, AppStream metainfo and the rest of packaging
# stay with M6 (docs/SPEC.md §10, postponed).

install_data('cz.ok1br.pass_for_linux.svg',
  install_dir : get_option('datadir') / 'icons' / 'hicolor' / 'scalable' / 'apps',
  install_tag : 'data')  # so `meson install --tags data` = icon without binary
install_data('cz.ok1br.pass_for_linux-symbolic.svg',
  install_dir : get_option('datadir') / 'icons' / 'hicolor' / 'symbolic' / 'apps',
  install_tag : 'data')

# The sibling installs left an icon-theme.cache in ~/.local/share/icons/
# hicolor; a cache that predates our icon would hide it, so refresh it at
# install time like sdr-for-linux does. Skipped automatically under DESTDIR.
# Note: `meson install --tags ...` skips install scripts (observed with
# meson 1.12) — after a tag-limited install, run
#   gtk4-update-icon-cache -f -t ~/.local/share/icons/hicolor
# by hand. A full `meson install` (M6) runs this normally.
gnome.post_install(gtk_update_icon_cache : true)
