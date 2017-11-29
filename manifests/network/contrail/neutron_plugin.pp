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
# [*auth_port_ssl*]
#  (optional) keystone ssl port.
#  Integer value.
#  Defaults to hiera('contrail::auth_port_ssl')
#
# [*auth_protocol*]
#  (optional) authentication protocol.
#  String value.
#  Defaults to hiera('contrail::auth_protocol')
#
# [*ca_file*]
#  (optional) ca file name
#  String value.
#  Defaults to hiera('contrail::service_certificate',false)
#
# [*cert_file*]
#  (optional) cert file name
#  String value.
#  Defaults to hiera('contrail::service_certificate',false)
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
  $auth_port_ssl                = hiera('contrail::auth_port_ssl'),
  $auth_protocol                = hiera('contrail::auth_protocol'),
  $auth_version                 = hiera('contrail::auth_version',2),
  $ca_file                      = hiera('tripleo::haproxy::service_certificate',false),
  $cert_file                    = hiera('tripleo::haproxy::service_certificate',false),
  $contrail_version             = hiera('contrail::contrail_version',4),
  $insecure                     = hiera('contrail::insecure'),
  $keystone_auth_type           = hiera('contrail::keystone_auth_type','password'),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $purge_config                 = false,
  $package_ensure               = 'present',
) {

  include ::neutron::deps
  include ::neutron::params

  File<| |> -> Ini_setting<| |>

  validate_array($contrail_extensions)

  package { 'neutron-plugin-contrail':
    ensure => $package_ensure,
    name   => $::neutron::params::opencontrail_plugin_package,
    tag    => ['neutron-package', 'openstack'],
  }
  package {'python-contrail':
    ensure => installed,
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
      'AUTHN_SERVER'   => $auth_host,
      'AUTHN_PROTOCOL' => $auth_protocol,
      'AUTHN_URL'      => $vnc_authn_url,
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

  if $auth_protocol == 'https' {
    $auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port_ssl,$auth_url_suffix])
    $api_srv_auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port_ssl,$api_srv_auth_url_suffix])
    $vnc_api_lib_config_auth_specific = {
      'auth' => {
        'AUTHN_PORT'     => $auth_port_ssl,
        'certfile'       => $cert_file,
        'cafile'         => $ca_file,
      },
    }

    neutron_plugin_opencontrail {
      'APISERVER/api_server_ip':                  value => $api_server;
      'APISERVER/api_server_port':                value => $api_port;
      'APISERVER/auth_token_url':                 value => $api_srv_auth_url;
      'APISERVER/contrail_extensions':            value => join($contrail_extensions, ',');
      'KEYSTONE/auth_url':                        value => $auth_url;
      'KEYSTONE/admin_user' :                     value => $admin_user;
      'KEYSTONE/admin_tenant_name':               value => $admin_tenant_name;
      'KEYSTONE/admin_password':                  value => $admin_password, secret =>true;
      'KEYSTONE/cafile':                          value => $ca_file;
      'KEYSTONE/certfile':                        value => $cert_file;
      'KEYSTONE/auth_type':                       value => $keystone_auth_type;
      'KEYSTONE/project_domain_name':             value => $keystone_project_domain_name;
      'KEYSTONE/region_name':                     value => $keystone_region;
      'KEYSTONE/user_domain_name':                value => $keystone_user_domain_name;
      'keystone_authtoken/admin_user':            value => $admin_user;
      'keystone_authtoken/admin_tenant':          value => $admin_tenant_name;
      'keystone_authtoken/admin_password':        value => $admin_password, secret =>true;
      'keystone_authtoken/auth_host':             value => $auth_host;
      'keystone_authtoken/auth_protocol':         value => $auth_protocol;
      'keystone_authtoken/auth_port':             value => $auth_port_ssl;
      'keystone_authtoken/auth_uri':              value => $auth_url;
      'keystone_authtoken/cafile':                value => $ca_file;
      'keystone_authtoken/certfile':              value => $cert_file;
      'keystone_authtoken/project_domain_name':   value => $keystone_project_domain_name;
      'keystone_authtoken/region_name':           value => $keystone_region;
      'keystone_authtoken/user_domain_name':      value => $keystone_user_domain_name;
    }
  } else {
    $auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port,$auth_url_suffix])
    $api_srv_auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port,$api_srv_auth_url_suffix])
    $vnc_api_lib_config_auth_specific = {
      'auth' => {
        'AUTHN_PORT'      => $auth_port,
      },
    }

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
