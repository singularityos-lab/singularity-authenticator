project('singularity-authenticator', ['vala', 'c'],
  version: '0.1.0',
  meson_version: '>= 0.59.0'
)

i18n = import('i18n')
add_project_arguments('-DGETTEXT_PACKAGE="singularity-authenticator"', language: 'c')
subdir('po')

gtk_dep = dependency('gtk4', version: '>= 4.16')
gee_dep = dependency('gee-0.8')
json_dep = dependency('json-glib-1.0')
soup_dep = dependency('libsoup-3.0')
secret_dep = dependency('libsecret-1')
pixbuf_dep = dependency('gdk-pixbuf-2.0')
gcrypt_dep = dependency('libgcrypt', version: '>= 1.6')
cairo_dep = dependency('cairo')
m_dep = meson.get_compiler('c').find_library('m', required: false)
zbar_dep = dependency('zbar', required: false)
if not zbar_dep.found() and not get_option('qr').disabled()
  if meson.get_compiler('c').links('int zbar_image_scanner_create(void); int main(void) { return zbar_image_scanner_create() == 0; }',
      args: ['-l:libzbar.so.0'], name: 'zbar runtime library')
    zbar_dep = declare_dependency(include_directories: include_directories('third_party/zbar'),
      link_args: ['-l:libzbar.so.0'])
  elif get_option('qr').enabled()
    error('ZBar was requested but neither its development files nor libzbar.so.0 were found')
  endif
endif

libsingularity_dep = dependency('singularity-1.0',
  fallback: ['libsingularity', 'libsingularity_dep']
)

if not meson.is_subproject() and libsingularity_dep.type_name() == 'internal'
  libsingularity_vapi_dir = join_paths(meson.project_build_root(), 'subprojects', 'libsingularity')
  add_project_arguments(['--vapidir=' + libsingularity_vapi_dir], language: 'vala')
endif

vault_bridge = static_library('vault-bridge', 'src/vault-bridge.c',
  dependencies: [dependency('glib-2.0'), gcrypt_dep])

core_sources = files(
  'src/otp.vala',
  'src/account.vala',
  'src/migration.vala',
  'src/vault.vala',
  'src/security.vala',
)

qr_code_sources = files(
  'src/qr-encoder.vala',
  'src/qr-render.vala',
)

vala_args = ['--vapidir=' + meson.current_source_dir() / 'vapi', '--pkg=vaultbridge']
link_with = [vault_bridge]

sources = core_sources + qr_code_sources + files(
  'src/store.vala',
  'src/icons.vala',
  'src/search.vala',
  'src/window.vala',
  'src/app.vala',
)
if zbar_dep.found()
  qr_bridge = static_library('qr-bridge', 'src/qr-bridge.c',
    dependencies: [dependency('glib-2.0'), zbar_dep])
  sources += files('src/qr.vala')
  link_with += qr_bridge
  vala_args += ['--pkg=qrbridge']
else
  sources += files('src/qr-missing.vala')
endif

executable('singularity-authenticator',
  sources,
  vala_args: vala_args,
  include_directories: include_directories('src'),
  link_with: link_with,
  dependencies: [gtk_dep, gee_dep, json_dep, soup_dep, secret_dep, pixbuf_dep, cairo_dep, m_dep, libsingularity_dep],
  install: true
)

install_data('data/dev.sinty.authenticator.desktop',
  install_dir: get_option('datadir') / 'applications'
)

install_data('data/dev.sinty.authenticator.gschema.xml',
  install_dir: get_option('datadir') / 'glib-2.0' / 'schemas'
)

install_data('data/dev.sinty.authenticator.json',
  install_dir: get_option('datadir') / 'singularity' / 'app-settings'
)

service_conf = configuration_data()
service_conf.set('bindir', get_option('prefix') / get_option('bindir'))
configure_file(
  input: 'data/dev.sinty.authenticator.service.in',
  output: 'dev.sinty.authenticator.service',
  configuration: service_conf,
  install: true,
  install_dir: get_option('datadir') / 'dbus-1' / 'services'
)

install_data('data/search-providers/dev.sinty.authenticator.ini',
  install_dir: get_option('datadir') / 'singularity' / 'search-providers'
)

install_data('data/icons/dev.sinty.authenticator.svg',
  install_dir: get_option('datadir') / 'icons' / 'hicolor' / 'scalable' / 'apps'
)

test_deps = [dependency('gio-2.0'), gee_dep, json_dep, secret_dep]
test_args = ['--vapidir=' + meson.current_source_dir() / 'vapi', '--pkg=vaultbridge']
fixtures = meson.current_source_dir() / 'tests' / 'fixtures'

otp_test = executable('otp-test', core_sources + files('tests/otp_test.vala'),
  vala_args: test_args, include_directories: include_directories('src'), link_with: vault_bridge,
  dependencies: test_deps)
test('otp', otp_test)

uri_test = executable('uri-test', core_sources + files('tests/uri_test.vala'),
  vala_args: test_args, include_directories: include_directories('src'), link_with: vault_bridge,
  dependencies: test_deps)
test('uri', uri_test)

vault_test = executable('vault-test', core_sources + files('tests/vault_test.vala'),
  vala_args: test_args, include_directories: include_directories('src'), link_with: vault_bridge,
  dependencies: test_deps)
test('vault', vault_test, args: [fixtures], timeout: 120)

migration_test = executable('migration-test', core_sources + files('tests/migration_test.vala'),
  vala_args: test_args, include_directories: include_directories('src'), link_with: vault_bridge,
  dependencies: test_deps)
test('migration', migration_test, args: [fixtures])

transfer_test = executable('transfer-test', core_sources + files('src/store.vala', 'tests/transfer_test.vala'),
  vala_args: test_args, include_directories: include_directories('src'), link_with: vault_bridge,
  dependencies: test_deps)
test_schemas = custom_target('test-schemas',
  input: 'data/dev.sinty.authenticator.gschema.xml',
  output: 'gschemas.compiled',
  command: [find_program('glib-compile-schemas'), '--strict', '--targetdir=@OUTDIR@', meson.current_source_dir() / 'data'],
)
test('transfer', transfer_test, args: [fixtures], depends: test_schemas,
  env: ['GSETTINGS_SCHEMA_DIR=' + meson.current_build_dir(), 'GSETTINGS_BACKEND=memory'])

if zbar_dep.found()
  qr_test = executable('qr-test', core_sources + qr_code_sources + files('src/qr.vala', 'tests/qr_test.vala'),
    vala_args: vala_args,
    include_directories: include_directories('src'),
    link_with: link_with,
    dependencies: test_deps + [pixbuf_dep, cairo_dep, m_dep])
  test('qr', qr_test, args: [fixtures])
endif
