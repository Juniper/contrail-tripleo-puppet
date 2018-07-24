# This class installs and configures Opencontrail Neutron Plugin for OSP13
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
# [*ssl_enabled*]
#  (optional) SSL should be used in internal Contrail services communications
#  Boolean value.
#  Defaults to hiera('contrail_ssl_enabled', false)
#
# [*auth_ca_file*]
#  (optional) auth ca file name
#  String value.
#  Defaults to hiera('contrail::auth_ca_file',false)
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
# [*purge_config*]
#   (optional) Whether to set only the specified config options
#   in the opencontrail config.
#   Defaults to false.
#
class tripleo::network::contrail::neutron_plugin (
  $step                         = Integer(hiera('step')),
  $aaa_mode                     = hiera('contrail::aaa_mode'),
  $contrail_extensions          = hiera('contrail::vrouter::contrail_extensions'),
  $admin_password               = hiera('contrail::admin_password'),
  $admin_tenant_name            = hiera('contrail::admin_tenant_name'),
  $admin_user                   = hiera('contrail::admin_user'),
  $api_server                   = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $api_port                     = hiera('contrail::api_port'),
  $auth_host                    = hiera('contrail::auth_host'),
  $auth_port                    = hiera('contrail::auth_port'),
  $auth_protocol                = hiera('contrail::auth_protocol'),
  $auth_ca_file                 = hiera('contrail::auth_ca_file', undef),
  $internal_api_ssl             = hiera('contrail_internal_api_ssl', false),
  $key_file                     = hiera('contrail::service_key_file', undef),
  $cert_file                    = hiera('contrail::service_cert_file', undef),
  $keystone_auth_type           = hiera('contrail::keystone_auth_type','password'),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
) {
  include ::neutron::deps
  include ::neutron::params

  File<| |> -> Ini_setting<| |>

  validate_array($contrail_extensions)

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

  file { '/etc/neutron/plugin.ini':
    ensure  => link,
    target  => $::neutron::params::opencontrail_config_file,
    tag     => 'neutron-config-file',
  }
  $api_paste_config_file = '/usr/share/neutron/api-paste.ini'

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

  exec { 'add neutron user to haproxy group':
    command => '/usr/sbin/usermod -a -G haproxy neutron',
  }

  $auth_url_suffix = '/v3'
  $api_srv_auth_url_suffix = '/v3/auth/tokens'
  $vnc_authn_url = '/v3/auth/tokens'
  $vnc_api_lib_config_common = {
    'global' => {
      'WEB_SERVER'  => $api_server,
      'WEB_PORT'    => $api_port,
    },
    'auth' => {
      'AUTHN_SERVER'    => $auth_host,
      'AUTHN_PORT'      => $auth_port,
      'AUTHN_PROTOCOL'  => $auth_protocol,
      'AUTHN_URL'       => $vnc_authn_url,
      'AUTHN_TYPE'      => 'keystone',
    },
  }

  $auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port,$auth_url_suffix])
  $api_srv_auth_url = join([$auth_protocol,'://',$auth_host,':',$auth_port,$api_srv_auth_url_suffix])
  if $internal_api_ssl {
    if $auth_ca_file {
      $insecure = false
      $cafile_vnc_api = {
        'global' => {
          'cafile' => $auth_ca_file,
        },
        'auth'   => {
          'cafile' => $auth_ca_file,
        },
      }
    } else {
      $insecure = true
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

  $vnc_api_lib_config = deep_merge($vnc_api_lib_config_common, $vnc_api_lib_config_auth_specific)
  $contrail_vnc_api_lib_config = { 'path' => '/etc/contrail/vnc_api_lib.ini' }
  create_ini_settings($vnc_api_lib_config, $contrail_vnc_api_lib_config)
}
