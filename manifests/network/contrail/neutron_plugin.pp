# This class installs and configures Opencontrail Neutron Plugin.
#
# === Parameters
#
# [*aaa_mode*]
#  (optional) aaa mode parameter
#  String value.
#  Defaults to hiera('contrail::aaa_mode')
#
# [*admin_password*]
#  (optional) admin password
#  String value.
#  Defaults to hiera('contrail::admin_password')
#
# [*admin_tenant_name*]
#  (optional) admin tenant name.
#  String value.
#  Defaults to hiera('contrail::admin_tenant_name')
#
# [*admin_token*]
#  (optional) admin token
#  String value.
#  Defaults to hiera('contrail::admin_token')
#
# [*admin_user*]
#  (optional) admin user name.
#  String value.
#  Defaults to hiera('contrail::admin_user')
#
# [*api_server*]
#  (optional) IP address of api server
#  String value.
#  Defaults to hiera('contrail_config_vip',hiera('internal_api_virtual_ip'))
#
# [*api_port*]
#  (optional) port of api server
#  String value.
#  Defaults to hiera('contrail::api_port')
#
# [*auth_host*]
#  (optional) keystone server ip address
#  String (IPv4) value.
#  Defaults to hiera('contrail::auth_host')
#
# [*auth_port*]
#  (optional) keystone port.
#  Integer value.
#  Defaults to hiera('contrail::auth_port')
#
# [*auth_version*]
#  (optional) authentication protocol version.
#  Integer value.
#  Defaults to hiera('contrail::auth_version',2)
#
# [*ssl_enabled*]
#  (optional) SSL should be used in internal Contrail services communications
#  Boolean value.
#  Defaults to hiera('contrail_ssl_enabled', false)
#
# [*ca_file*]
#  (optional) ca file name
#  String value.
#  Defaults to hiera('contrail::service_cert_file',false)
#
# [*cert_file*]
#  (optional) cert file name
#  String value.
#  Defaults to hiera('contrail::service_cert_file',false)
#
# [*key_file*]
#  (optional) key file name
#  String value.
#  Defaults to hiera('contrail::service_key_file',false)
#
# [*api_server_ip*]
#   IP address of the API Server
#   Defaults to $::os_service_default
#
# [*api_server_port*]
#   Port of the API Server.
#   Defaults to $::os_service_default
#
# [*contrail_extensions*]
#   Array of OpenContrail extensions to be supported
#   Defaults to $::os_service_default
#   Example:
#
#     class {'neutron::plugins::opencontrail' :
#       contrail_extensions => ['ipam:neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_ipam.NeutronPluginContrailIpam']
#     }
#
# [*contrail_version*]
#  (optional) contrail version.
#  Integer value.
#  Defaults to hiera('contrail::contrail_version',4)
#
# [*insecure*]
#  (optional) insecure connections allowed
#  String value.
#  Defaults to hiera('contrail::insecure')
#
# [*keystone_auth_url*]
#   Url of the keystone auth server
#   Defaults to $::os_service_default
#
# [*keystone_admin_user*]
#   Admin user name
#   Defaults to $::os_service_default
#
# [*keystone_admin_tenant_name*]
#   Admin_tenant_name
#   Defaults to $::os_service_default
#
# [*keystone_admin_password*]
#   Admin password
#   Defaults to $::os_service_default
#
# [*keystone_admin_token*]
#   Admin token
#   Defaults to $::os_service_default
#
# [*keystone_auth_type*]
#  (optional) keystone auth type.
#  String value.
#  Defaults to hiera('contrail::keystone_auth_type','password')
#
# [*keystone_project_domain_name*]
#  (optional) keystone project domain name.
#  String value.
#  Defaults to hiera('contrail::keystone_project_domain_name','Default')
#
# [*keystone_region*]
#  (optional) keystone region.
#  String value.
#  Defaults to hiera('contrail::keystone_region','regionOne')
#
# [*keystone_user_domain_name*]
#  (optional) keystone user domain name.
#  String value.
#  Defaults to hiera('contrail::keystone_user_domain_name','Default')
#
# [*package_ensure*]
#   (optional) Ensure state for package.
#   Defaults to 'present'.
#
# [*purge_config*]
#   (optional) Whether to set only the specified config options
#   in the opencontrail config.
#   Defaults to false.
#
class tripleo::network::contrail::neutron_plugin (
  $step  = Integer(hiera('step')),
  $aaa_mode                     = hiera('contrail::aaa_mode'),
  $contrail_extensions          = hiera('contrail::vrouter::contrail_extensions'),
  $admin_password               = hiera('contrail::admin_password'),
  $admin_tenant_name            = hiera('contrail::admin_tenant_name'),
  $admin_token                  = hiera('contrail::admin_token'),
  $admin_user                   = hiera('contrail::admin_user'),
  $api_server                   = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $api_port                     = hiera('contrail::api_port'),
  $auth_host                    = hiera('contrail::auth_host'),
  $auth_port                    = hiera('contrail::auth_port'),
  $auth_protocol                = hiera('contrail::auth_protocol'),
  $auth_version                 = hiera('contrail::auth_version',2),
  $auth_ca_file                 = hiera('contrail::auth_ca_file', undef),
  $auth_ca_cert                 = hiera('contrail::auth_ca_cert', undef),
  $ssl_enabled                  = hiera('contrail_ssl_enabled', false),
  $internal_api_ssl             = hiera('contrail_internal_api_ssl', false),
  $ca_file                      = hiera('contrail::ca_cert_file', undef),
  $ca_cert                      = hiera('contrail::ca_cert', undef),
  $ca_key_file                  = hiera('contrail::ca_key_file', undef),
  $ca_key                       = hiera('contrail::ca_key', undef),
  $key_file                     = hiera('contrail::service_key_file', undef),
  $cert_file                    = hiera('contrail::service_cert_file', undef),
  $contrail_version             = hiera('contrail::contrail_version',4),
  $insecure                     = hiera('contrail::insecure'),
  $keystone_auth_type           = hiera('contrail::keystone_auth_type','password'),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $purge_config                 = false,
  $package_ensure               = 'present',
  $host_ip                      = hiera('tripleo::profile::base::neutron::server::tls_proxy_bind_ip', hiera('neutron::bind_host')),
) {
  if $step == 3 {
    include ::neutron::deps
    include ::neutron::params

    File<| |> -> Ini_setting<| |>
    Class['tripleo::network::contrail::certmonger'] -> Service<| tag == 'neutron' |>

    validate_array($contrail_extensions)

    package { 'neutron-plugin-contrail':
      ensure => $package_ensure,
      name   => $::neutron::params::opencontrail_plugin_package,
      tag    => ['neutron-package', 'openstack'],
    }
    package {'python-contrail':
      ensure => installed,
    }

    class { '::tripleo::network::contrail::certmonger':
      host_ip      => $host_ip,
      ssl_enabled  => $ssl_enabled or $internal_api_ssl,
      key_file     => $key_file,
      cert_file    => $cert_file,
      ca_file      => $ca_file,
      ca_cert      => $ca_cert,
      ca_key_file  => $ca_key_file,
      ca_key       => $ca_key,
      auth_ca_cert => $auth_ca_cert,
      auth_ca_file => $auth_ca_file,
      owner        => 'neutron',
      group        => 'neutron',
    }

    ensure_resource('file', '/etc/neutron/plugins/opencontrail', {
      ensure => directory,
      owner  => 'root',
      group  => 'neutron',
      mode   => '0640'}
    )
    ensure_resource('file', '/etc/contrail', {
      ensure => directory,
      owner  => 'root',
      group  => 'neutron',
      mode   => '0640'}
    )

    if $::osfamily == 'Debian' {
      file_line { '/etc/default/neutron-server:NEUTRON_PLUGIN_CONFIG':
        path  => '/etc/default/neutron-server',
        match => '^NEUTRON_PLUGIN_CONFIG=(.*)$',
        line  => "NEUTRON_PLUGIN_CONFIG=${::neutron::params::opencontrail_config_file}",
        tag   => 'neutron-file-line',
      }
    }

    if $::osfamily == 'Redhat' {
      file { '/etc/neutron/plugin.ini':
        ensure  => link,
        target  => $::neutron::params::opencontrail_config_file,
        require => Package[$::neutron::params::opencontrail_plugin_package],
        tag     => 'neutron-config-file',
      }
      $api_paste_config_file = '/usr/share/neutron/api-paste.ini'
    }

    ini_setting { 'quota_driver':
      ensure  => present,
      path    => '/etc/neutron/neutron.conf',
      section => 'quotas',
      setting => 'quota_driver',
      value   => 'neutron_plugin_contrail.plugins.opencontrail.quota.driver.QuotaDriver',
    }
    if $aaa_mode == 'rbac' {
      ini_setting { 'filter:user_token':
        ensure  => present,
        path    => $api_paste_config_file,
        section => 'filter:user_token',
        setting => 'paste.filter_factory',
        value   => 'neutron_plugin_contrail.plugins.opencontrail.neutron_middleware:token_factory',
      }
      ini_setting { 'composite:neutronapi_v2_0':
        ensure  => present,
        path    => $api_paste_config_file,
        section => 'composite:neutronapi_v2_0',
        setting => 'keystone',
        value   => 'user_token cors http_proxy_to_wsgi request_id catch_errors authtoken keystonecontext extensions neutronapiapp_v2_0',
      }
    }
    resources { 'neutron_plugin_opencontrail':
      purge => $purge_config,
    }

    exec { 'add neutron user to haproxy group':
      command => '/usr/sbin/usermod -a -G haproxy neutron',
    }

    if $auth_version == 2 {
      $auth_url_suffix = '/v2.0'
      $api_srv_auth_url_suffix = '/v2.0/tokens'
      $vnc_authn_url = '/v2.0/tokens'
    } else {
      $auth_url_suffix = '/v3'
      $api_srv_auth_url_suffix = '/v3/auth/tokens'
      $vnc_authn_url = '/v3/auth/tokens'
    }
    $vnc_api_lib_config_common = {
      'auth' => {
        'AUTHN_SERVER'    => $auth_host,
        'AUTHN_PORT'      => $auth_port,
        'AUTHN_PROTOCOL'  => $auth_protocol,
        'AUTHN_URL'       => $vnc_authn_url,
      },
    }

    if $contrail_version < 4 {
      $vnc_api_lib_config_ver_specific = {}
    } else {
      $vnc_api_cfg_global = {
        'global' => {
          'WEB_SERVER'  => $api_server,
          'WEB_PORT'    => $api_port,
        }
      }
      if $auth_host and $auth_host != '' {
        $vnc_api_lib_config_type = {
          'auth' => {
            'AUTHN_TYPE'      => 'keystone',
            'insecure'        => $insecure,
          },
        }
      } else {
        $vnc_api_lib_config_type = {
          'auth' => {
            'AUTHN_TYPE' => 'noauth',
          },
        }
      }
      $vnc_api_lib_config_ver_specific = deep_merge($vnc_api_cfg_global, $vnc_api_lib_config_type)
    }
    $auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port,$auth_url_suffix])
    $api_srv_auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port,$api_srv_auth_url_suffix])
    if $internal_api_ssl {
      if $auth_ca_file {
        $cafile_vnc_api = {
          'global' => {
            'cafile' => $auth_ca_file,
          },
          'auth'   => {
            'cafile' => $auth_ca_file,
          },
        }
      } else {
        $cafile_vnc_api = {}
      }
      $vnc_api_lib_preconfig_auth_specific = {
        'global' => {
          'insecure' => $insecure,
          'certfile' => $cert_file,
          'keyfile'  => $key_file,
        },
        'auth'   => {
          'insecure'   => $insecure,
          'certfile'   => $cert_file,
          'keyfile'    => $key_file,
        },
      }
      $vnc_api_lib_config_auth_specific = deep_merge($vnc_api_lib_preconfig_auth_specific, $cafile_vnc_api)
      neutron_plugin_opencontrail {
        'APISERVER/api_server_ip':                  value => $api_server;
        'APISERVER/api_server_port':                value => $api_port;
        'APISERVER/auth_token_url':                 value => $api_srv_auth_url;
        'APISERVER/contrail_extensions':            value => join($contrail_extensions, ',');
        'APISERVER/use_ssl':                        value => $internal_api_ssl;
        'APISERVER/insecure':                       value => $insecure;
        'APISERVER/cafile':                         value => $auth_ca_file;
        'APISERVER/certfile':                       value => $cert_file;
        'APISERVER/keyfile':                        value => $key_file;
        'KEYSTONE/auth_url':                        value => $auth_url;
        'KEYSTONE/admin_user' :                     value => $admin_user;
        'KEYSTONE/admin_tenant_name':               value => $admin_tenant_name;
        'KEYSTONE/admin_password':                  value => $admin_password, secret =>true;
        'KEYSTONE/cafile':                          value => $auth_ca_file;
        'KEYSTONE/certfile':                        value => $cert_file;
        'KEYSTONE/auth_type':                       value => $keystone_auth_type;
        'KEYSTONE/insecure':                        value => $insecure;
        'KEYSTONE/project_domain_name':             value => $keystone_project_domain_name;
        'KEYSTONE/region_name':                     value => $keystone_region;
        'KEYSTONE/user_domain_name':                value => $keystone_user_domain_name;
        'keystone_authtoken/admin_user':            value => $admin_user;
        'keystone_authtoken/admin_tenant':          value => $admin_tenant_name;
        'keystone_authtoken/admin_password':        value => $admin_password, secret =>true;
        'keystone_authtoken/auth_host':             value => $auth_host;
        'keystone_authtoken/auth_protocol':         value => $auth_protocol;
        'keystone_authtoken/auth_port':             value => $auth_port;
        'keystone_authtoken/auth_uri':              value => $auth_url;
        'keystone_authtoken/insecure':              value => $insecure;
        'keystone_authtoken/cafile':                value => $auth_ca_file;
        'keystone_authtoken/certfile':              value => $cert_file;
        'keystone_authtoken/keyfile':               value => $key_file;
        'keystone_authtoken/project_domain_name':   value => $keystone_project_domain_name;
        'keystone_authtoken/region_name':           value => $keystone_region;
        'keystone_authtoken/user_domain_name':      value => $keystone_user_domain_name;
      }
    } else {
      $vnc_api_lib_config_auth_specific = {}
      neutron_plugin_opencontrail {
        'APISERVER/api_server_ip':                  value => $api_server;
        'APISERVER/api_server_port':                value => $api_port;
        'APISERVER/auth_token_url':                 value => $api_srv_auth_url;
        'APISERVER/contrail_extensions':            value => join($contrail_extensions, ',');
        'KEYSTONE/auth_url':                        value => $auth_url;
        'KEYSTONE/admin_user' :                     value => $admin_user;
        'KEYSTONE/admin_tenant_name':               value => $admin_tenant_name;
        'KEYSTONE/admin_password':                  value => $admin_password, secret =>true;
        'KEYSTONE/auth_type':                       value => $keystone_auth_type;
        'KEYSTONE/project_domain_name':             value => $keystone_project_domain_name;
        'KEYSTONE/region_name':                     value => $keystone_region;
        'KEYSTONE/user_domain_name':                value => $keystone_user_domain_name;
        'keystone_authtoken/admin_user':            value => $admin_user;
        'keystone_authtoken/admin_tenant':          value => $admin_tenant_name;
        'keystone_authtoken/admin_password':        value => $admin_password, secret =>true;
        'keystone_authtoken/auth_host':             value => $auth_host;
        'keystone_authtoken/auth_uri':              value => $auth_url;
        'keystone_authtoken/auth_protocol':         value => $auth_protocol;
        'keystone_authtoken/auth_port':             value => $auth_port;
        'keystone_authtoken/project_domain_name':   value => $keystone_project_domain_name;
        'keystone_authtoken/region_name':           value => $keystone_region;
        'keystone_authtoken/user_domain_name':      value => $keystone_user_domain_name;
      }
    }

    $vnc_api_lib_config = deep_merge(
        deep_merge($vnc_api_lib_config_common, $vnc_api_lib_config_auth_specific),
        $vnc_api_lib_config_ver_specific
    )
    $contrail_vnc_api_lib_config = { 'path' => '/etc/contrail/vnc_api_lib.ini' }
    create_ini_settings($vnc_api_lib_config, $contrail_vnc_api_lib_config)
  }
}
