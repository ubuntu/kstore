project('kstore',
        ['c'],
        version: '0.1.0',
        license: 'GPLv2',
        meson_version: '>= 0.53.0',
)

cc = meson.get_compiler('c')

prefix = get_option('prefix')
libexec_dir = join_paths(prefix, get_option('libexecdir'))
pam_modules_dir = join_paths(get_option('libdir'), 'security')

version_arr = meson.project_version().split('.')
major_version = version_arr[0].to_int()
minor_version = version_arr[1].to_int()
micro_version = version_arr[2].to_int()

libpam = [ cc.find_library('pam') ]
if not(cc.has_function('pam_start',
        dependencies: libpam,
        prefix: '''
                #include <security/pam_appl.h>
        '''
))
        error('Couldn\'t find security/pam_appl.h or pam_start in lib lib pam. Install libpam0g-dev')
endif

conf = configuration_data()
conf.set_quoted('KEYSTORE_BIN', join_paths(libexec_dir, 'user_keystore'))
configure_file(output: 'config.h',
               configuration: conf)
config_h_dir = include_directories('.')

pam_kstore = shared_module('pam_kstore',
                        ['pam_kstore.c'],
                        include_directories : '.',
                        dependencies: libpam,
                        install : true,
                        install_dir: pam_modules_dir,
                        )

install_data('user_kstore', install_dir: libexec_dir, install_mode: ['rwxr-xr-x', 0, 0])
