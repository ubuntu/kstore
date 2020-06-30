project('kstore',
        ['c'],
        version: '0.1.0',
        license: 'GPLv2',
        meson_version: '>= 0.47.0',
)

cc = meson.get_compiler('c')

prefix = get_option('prefix')
libexec_dir = join_paths(prefix, get_option('libexecdir'))
source_root = join_paths(meson.source_root(), 'kstore')

version_arr = meson.project_version().split('.')
major_version = version_arr[0].to_int()
minor_version = version_arr[1].to_int()
micro_version = version_arr[2].to_int()

inc = include_directories('.')

libpam = [ cc.find_library('pam') ]
defs = []
if not(cc.has_function('pam_start',
        args: defs,
        dependencies: libpam,
        prefix: '''
                #include <security/pam_appl.h>
        '''
))
        error('Couldn\'t find security/pam_appl.h or pam_start in lib lib pam')
endif

conf = configuration_data()
conf.set_quoted('KEYSTORE_BIN', join_paths(libexec_dir, 'user_keystore'))
configure_file(output: 'config.h',
               configuration: conf)
config_h_dir = include_directories('.')

kstore_sources = ['pam_kstore.c']
kstorelib = shared_library('pam_keystore',
                        kstore_sources,
                        include_directories : inc,
                        dependencies: libpam,
                        install : true)