#
# Copyright (C) 2015 Juniper Networks
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# == Class: tripleo::network::contrail::config
#
# Configure Contrail Config services
#
# == Parameters:
#
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
# [*analytics_server_list*]
#  (optional) list of analytics server
#  Array of String values.
#  Defaults to hiera('contrail_analytics_node_ips')
#
# [*api_server*]
#  (optional) VIP of Config API
#  String (IPv4) value.
#  Defaults to hiera('contrail_config_vip',hiera('internal_api_virtual_ip'))
#
# [*api_port*]
#  (optional) Port of Config API
#  String value.
#  Defaults to hiera('contrail::api_port')
#
# [*auth*]
#  (optional) Authentication method.
#  Defaults to hiera('contrail::auth')
#
# [*auth_host*]
#  (optional) keystone server ip address
#  String (IPv4) value.
#  Defaults to hiera('contrail::auth_host')
#
# [*auth_port*]
#  (optional) keystone port.
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
#  Defaults to hiera('contrail::ca_cert_file',false)
#
# [*key_file*]
#  (optional) key file name
#  String value.
#  Defaults to hiera('contrail::service_key_file',false)
#
# [*cert_file*]
#  (optional) cert file name
#  String value.
#  Defaults to hiera('contrail::service_cert_file',false)
#
# [*cassandra_server_list*]
#  (optional) List IPs+port of Cassandra servers
#  Array of strings value.
#  Defaults to hiera('contrail::cassandra_server_list')
#
# [*config_hostnames*]
#  (optional) Config hostname list
#  Array of string value.
#  Defaults to hiera('contrail_config_short_node_names')
#
# [*control_server_list*]
#  (optional) IPv4 addresses of control server.
#  Array of string (IPv4) value.
#  Defaults to hiera('contrail_control_node_ips')
#
# [*disc_server_ip*]
#  (optional) IPv4 address of discovery server.
#  String (IPv4) value.
#  Defaults to hiera('contrail::disc_server_ip')
#
# [*disc_server_port*]
#  (optional) port of discovery server
#  String value.
#  Defaults to hiera('contrail::disc_server_port')
#
# [*host_ip*]
#  (optional) IPv4 address of Config server
#  String (IPv4) value.
#  Defaults to hiera('contrail::config::host_ip')
#
# [*ifmap_password*]
#  (optional) ifmap password
#  String value.
#  Defaults to hiera('contrail::config::ifmap_password')
#
# [*ifmap_server_ip*]
#  (optional) ifmap server ip address.
#  String value.
#  Defaults to hiera('contrail::config::host_ip')
#
# [*ifmap_username*]
#  (optional) ifmap username
#  String value.
#  Defaults to hiera('contrail::config::ifmap_password')
#
# [*insecure*]
#  (optional) insecure mode.
#  Defaults to hiera('contrail::insecure')
#
# [*ipfabric_service_port*]
#  (optional) linklocal ip fabric port
#  String value
#  Defaults to 8775
#
# [*listen_ip_address*]
#  (optional) IP address to listen on.
#  String (IPv4) value.
#  Defaults to hiera('contrail::config::listen_ip_address')
#
# [*listen_port*]
#  (optional) Listen port for config-api
#  Defaults to hiera('contrail::api_port')
#
# [*linklocal_service_name*]
#  (optional) name of link local service
#  String value
#  Defaults to metadata
#
# [*linklocal_service_port*]
#  (optional) port of link local service
#  String value
#  Defaults to 80
#
# [*linklocal_service_name*]
#  (optional) name of link local service
#  String value
#  Defaults to metadata
#
# [*linklocal_service_ip*]
#  (optional) IPv4 address of link local service
#  String (IPv4) value
#  Defaults to 169.254.169.254
#
# [*memcached_servers*]
#  (optional) IPv4 address of memcached servers
#  String (IPv4) value + port
#  Defaults to hiera('contrail::memcached_server')
#
# [*internal_vip*]
#  (optional) Public virtual ip
#  String value.
#  Defaults to hiera('internal_api_virtual_ip')
#
# [*step*]
#  (optional) Step stack is in
#  Integer value.
#  Defaults to hiera('step')
#
# [*rabbit_server*]
#  (optional) rabbit server
#  Array of string value.
#  Defaults to hiera('rabbitmq_node_ips')
#
# [*rabbit_user*]
#  (optional) rabbit user
#  String value.
#  Defaults to hiera('contrail::rabbit_user')
#
# [*rabbit_password*]
#  (optional) rabbit password
#  String value.
#  Defaults to hiera('contrail::rabbit_password')
#
# [*rabbit_port*]
#  (optional) rabbit server port
#  String value.
#  Defaults to hiera('contrail::rabbit_port')
#
# [*redis_server*]
#  (optional) IPv4 address of redis server.
#  String (IPv4) value.
#  Defaults to hiera('contrail::config::redis_server')
#
# [*zk_server_ip*]
#  (optional) List IPs+port of Zookeeper servers
#  Array of strings value.
#  Defaults to hiera('contrail_database_node_ips')
#
class tripleo::network::contrail::config(
  $step                         = hiera('step'),
  $aaa_mode                     = hiera('contrail::aaa_mode'),
  $admin_password               = hiera('contrail::admin_password'),
  $admin_tenant_name            = hiera('contrail::admin_tenant_name'),
  $admin_token                  = hiera('contrail::admin_token'),
  $admin_user                   = hiera('contrail::admin_user'),
  $analytics_server_list        = hiera('contrail_analytics_node_ips'),
  $api_server                   = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $api_port                     = hiera('contrail::api_port'),
  $auth                         = hiera('contrail::auth'),
  $auth_host                    = hiera('contrail::auth_host'),
  $auth_port                    = hiera('contrail::auth_port'),
  $auth_protocol                = hiera('contrail::auth_protocol'),
  $auth_version                 = hiera('contrail::auth_version',2),
  $auth_ca_file                 = hiera('contrail::auth_ca_file', undef),
  $auth_ca_cert                 = hiera('contrail::auth_ca_cert', undef),
  $cassandra_server_list        = hiera('contrail_database_node_ips'),
  $ssl_enabled                  = hiera('contrail_ssl_enabled', false),
  $internal_api_ssl             = hiera('contrail_internal_api_ssl', false),
  $ca_file                      = hiera('contrail::ca_cert_file', undef),
  $ca_cert                      = hiera('contrail::ca_cert', undef),
  $ca_key_file                  = hiera('contrail::ca_key_file', undef),
  $ca_key                       = hiera('contrail::ca_key', undef),
  $key_file                     = hiera('contrail::service_key_file', undef),
  $cert_file                    = hiera('contrail::service_cert_file', undef),
  $config_hostnames             = hiera('contrail_config_short_node_names'),
  $control_server_list          = hiera('contrail_control_node_ips'),
  $contrail_version             = hiera('contrail::contrail_version',4),
  $disc_server_ip               = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $disc_server_port             = hiera('contrail::disc_server_port'),
  $host_ip                      = hiera('contrail::config::host_ip'),
  $ifmap_password               = hiera('contrail::config::ifmap_password',false),
  $ifmap_server_ip              = hiera('contrail::config::host_ip'),
  $ifmap_username               = hiera('contrail::config::ifmap_username',false),
  $insecure                     = hiera('contrail::insecure'),
  $ipfabric_service_port        = 8775,
  $listen_ip_address            = hiera('contrail::config::listen_ip_address'),
  $listen_port                  = hiera('contrail::api_port'),
  $linklocal_service_port       = 80,
  $linklocal_service_name       = 'metadata',
  $linklocal_service_ip         = '169.254.169.254',
  $internal_vip                 = hiera('internal_api_virtual_ip'),
  $keystone_auth_type           = hiera('contrail::keystone_auth_type','password'),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $memcached_servers            = hiera('contrail::memcached_server', undef),
  $rabbit_server                = hiera('rabbitmq_node_ips'),
  $rabbit_user                  = hiera('contrail::rabbit_user'),
  $rabbit_password              = hiera('contrail::rabbit_password'),
  $rabbit_port                  = hiera('contrail::rabbit_port'),
  $rabbit_use_ssl               = hiera('contrail::rabbit_use_ssl', false),
  $rabbit_ca_file               = hiera('contrail::rabbit_ca_file', undef),
  $redis_server                 = hiera('contrail::config::redis_server'),
  $zk_server_ip                 = hiera('contrail_database_node_ips'),
)
{
  validate_ip_address($listen_ip_address)
  validate_ip_address($disc_server_ip)
  validate_ip_address($ifmap_server_ip)
  $basicauthusers_property_control = map($control_server_list) |$item| { "${item}.control:${item}.control" }
  $basicauthusers_property_dns = $control_server_list.map |$item| { "${item}.dns:${item}.dns" }
  $basicauthusers_property = concat($basicauthusers_property_control, $basicauthusers_property_dns)
  $cassandra_server_list_9160 = join([join($cassandra_server_list, ':9160 '),':9160'],'')
  $collector_server_list_8086 = join([join($analytics_server_list, ':8086 '),':8086'],'')
  $rabbit_server_list_5672 = join([join($rabbit_server, ':5672,'),':5672'],'')
  $zk_server_ip_2181 = join([join($zk_server_ip, ':2181,'),':2181'],'')
  $analytics_server_list_8081 = join([join($analytics_server_list, ':8081 '),':8081'],'')
  if $auth_version == 2 {
    $keystone_config_ver = {}
    $auth_url_suffix = 'v2.0'
    $vnc_authn_url = '/v2.0/tokens'
  } else {
    $keystone_config_ver = {
      'KEYSTONE' => {
        'auth_type'               => $keystone_auth_type,
        'project_domain_name'     => $keystone_project_domain_name,
        'user_domain_name'        => $keystone_user_domain_name,
      },
    }
    $auth_url_suffix = 'v3'
    $vnc_authn_url = '/v3/auth/tokens'
  }
  $auth_url = "${auth_protocol}://${auth_host}:${auth_port}/${auth_url_suffix}"
  if $internal_api_ssl {
    if $auth_ca_file {
      $cafile_keystone = {
        'KEYSTONE' => {
          'cafile' => $auth_ca_file,
        }
      }
      $cafile_vnc_api = {
        'global' => {
          'cafile' => $auth_ca_file,
        },
        'auth'   => {
          'cafile' => $auth_ca_file,
        },
      }
    } else {
      $cafile_keystone = {}
      $cafile_vnc_api = {}
    }
    $keystone_preconfig_proto = {
      'KEYSTONE' => {
        'admin_password'    => $admin_password,
        'admin_tenant_name' => $admin_tenant_name,
        'admin_user'        => $admin_user,
        'auth_host'         => $auth_host,
        'auth_port'         => $auth_port,
        'auth_protocol'     => $auth_protocol,
        'auth_url'          => $auth_url,
        'insecure'          => $insecure,
        'certfile'          => $cert_file,
        'keyfile'           => $key_file,
        'region_name'       => $keystone_region,
      },
    }
    $keystone_config_proto = deep_merge($keystone_preconfig_proto, $cafile_keystone)
    $vnc_api_lib_preconfig = {
      'global' => {
        'insecure' => $insecure,
        'certfile' => $cert_file,
        'keyfile'  => $key_file,
      },
      'auth'   => {
        'AUTHN_SERVER'   => $auth_host,
        'AUTHN_PORT'     => $auth_port,
        'AUTHN_PROTOCOL' => $auth_protocol,
        'AUTHN_URL'      => $vnc_authn_url,
        'insecure'       => $insecure,
        'certfile'       => $cert_file,
        'keyfile'        => $key_file,
      },
    }
    $vnc_api_lib_config = deep_merge($vnc_api_lib_preconfig, $cafile_vnc_api)
  } else {
    $keystone_config_proto = {
      'KEYSTONE' => {
        'admin_password'    => $admin_password,
        'admin_tenant_name' => $admin_tenant_name,
        'admin_user'        => $admin_user,
        'auth_host'         => $auth_host,
        'auth_port'         => $auth_port,
        'auth_protocol'     => $auth_protocol,
        'auth_url'          => $auth_url,
        'insecure'          => $insecure,
        'region_name'       => $keystone_region,
      },
    }
    $vnc_api_lib_config = {
      'auth' => {
        'AUTHN_SERVER'    => $auth_host,
        'AUTHN_PORT'      => $auth_port,
        'AUTHN_PROTOCOL'  => $auth_protocol,
        'AUTHN_URL'       => $vnc_authn_url,
      },
    }
  }
  if $memcached_servers {
    # contrail code use memcache_servers and set memcached_servers for middleware
    $keystone_config_memcached = {
       'KEYSTONE' => {
          'memcache_servers'  => $memcached_servers,
      },
    }
  } else {
    $keystone_config_memcached = {}
  }
  $keystone_config = deep_merge(deep_merge($keystone_config_proto, $keystone_config_ver), $keystone_config_memcached)
  $sandesh_config = {
    'introspect_ssl_enable' => $ssl_enabled,
    'sandesh_ssl_enable'    => $ssl_enabled,
    'sandesh_keyfile'       => $key_file,
    'sandesh_certfile'      => $cert_file,
    'sandesh_ca_cert'       => $ca_file,
  }
  if $step == 1 {
    class { '::tripleo::network::contrail::certmonger':
      host_ip       => $host_ip,
      ssl_enabled   => $ssl_enabled or $internal_api_ssl,
      key_file      => $key_file,
      cert_file     => $cert_file,
      ca_file       => $ca_file,
      ca_cert       => $ca_cert,
      ca_key_file   => $ca_key_file,
      ca_key        => $ca_key,
      auth_ca_cert  => $auth_ca_cert,
      auth_ca_file  => $auth_ca_file,
    }
  }
  if $step >= 3 {
    if $contrail_version == 3 {
      if $rabbit_use_ssl {
        $rabbit_config = {
          'kombu_ssl_certfile' => $cert_file,
          'kombu_ssl_keyfile'  => $key_file,
          'kombu_ssl_ca_certs' => $rabbit_ca_file,
        }
      } else {
        $rabbit_config = {}
      }
      $api_config_default_common =  {
        'aaa_mode'              => $aaa_mode,
        'auth'                  => $auth,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'disc_server_ip'        => $disc_server_ip,
        'disc_server_port'      => $disc_server_port,
        'ifmap_password'        => $ifmap_password,
        'ifmap_server_ip'       => $ifmap_server_ip,
        'ifmap_username'        => $ifmap_username,
        'listen_ip_addr'        => $listen_ip_address,
        'listen_port'           => $listen_port,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
      }
      $api_config_default = deep_merge($api_config_default_common, $rabbit_config)
      $device_manager_config_default_common =  {
        'api_server_ip'         => $api_server,
        'api_server_port'       => $api_port,
        'api_server_use_ssl'    => $internal_api_ssl,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'disc_server_ip'        => $disc_server_ip,
        'disc_server_port'      => $disc_server_port,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
      }
      $device_manager_config_default = deep_merge($device_manager_config_default_common, $rabbit_config)
      $svc_monitor_config_default_common =  {
        'api_server_ip'         => $api_server,
        'api_server_port'       => $api_port,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'disc_server_ip'        => $disc_server_ip,
        'disc_server_port'      => $disc_server_port,
        'ifmap_password'        => $ifmap_password,
        'ifmap_server_ip'       => $ifmap_server_ip,
        'ifmap_username'        => $ifmap_username,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
        'api_server_use_ssl'    => $internal_api_ssl,
      }
      $svc_monitor_config_default = deep_merge($svc_monitor_config_default_common, $rabbit_config)
      $schema_config_default_common =  {
        'api_server_ip'         => $api_server,
        'api_server_port'       => $api_port,
        'api_server_use_ssl'    => $internal_api_ssl,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'disc_server_ip'        => $disc_server_ip,
        'disc_server_port'      => $disc_server_port,
        'ifmap_password'        => $ifmap_password,
        'ifmap_server_ip'       => $ifmap_server_ip,
        'ifmap_username'        => $ifmap_username,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
      }
      $schema_config_default = deep_merge($schema_config_default_common, $rabbit_config)
      class {'::contrail::config':
        contrail_version        => $contrail_version,
        api_config              => {
          'DEFAULTS' => $api_config_default,
          'SANDESH'  => $sandesh_config,
        },
        basicauthusers_property => $basicauthusers_property,
        config_nodemgr_config   => {
          'DISCOVERY' => {
            'server' => $disc_server_ip,
            'port'   => $disc_server_port,
          },
          'SANDESH'   => $sandesh_config,
        },
        device_manager_config   => {
          'DEFAULTS' => $device_manager_config_default,
          'SANDESH'  => $sandesh_config,
        },
        discovery_config        => {
          'DEFAULTS' => {
            'cassandra_server_list' => $cassandra_server_list_9160,
            'zk_server_ip'          => $zk_server_ip_2181,
            },
          'SANDESH'  => $sandesh_config,
        },
        keystone_config         => $keystone_config,
        schema_config           => {
          'DEFAULTS' => $schema_config_default,
          'SANDESH'  => $sandesh_config,
        },
        svc_monitor_config      => {
          'DEFAULTS' => $svc_monitor_config_default,
          'SANDESH'  => $sandesh_config,
        },
        vnc_api_lib_config      => $vnc_api_lib_config,
      }
    } else {
      if $rabbit_use_ssl {
        $rabbit_config = {
          'kombu_ssl_certfile' => $cert_file,
          'kombu_ssl_keyfile'  => $key_file,
          'kombu_ssl_ca_certs' => $rabbit_ca_file,
        }
      } else {
        $rabbit_config = {}
      }
      $api_config_default_common =  {
        'aaa_mode'              => $aaa_mode,
        'auth'                  => $auth,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'collectors'            => $collector_server_list_8086,
        'listen_ip_addr'        => $listen_ip_address,
        'listen_port'           => $listen_port,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
      }
      $api_config_default = deep_merge($api_config_default_common, $rabbit_config)
      $device_manager_config_default_common =  {
        'api_server_ip'         => $api_server,
        'api_server_port'       => $api_port,
        'api_server_use_ssl'    => $internal_api_ssl,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'collectors'            => $collector_server_list_8086,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
      }
      $device_manager_config_default = deep_merge($device_manager_config_default_common, $rabbit_config)
      $svc_monitor_config_default_common =  {
        'api_server_ip'         => $api_server,
        'api_server_port'       => $api_port,
        'api_server_use_ssl'    => $internal_api_ssl,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'collectors'            => $collector_server_list_8086,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
     }
      $svc_monitor_config_default = deep_merge($svc_monitor_config_default_common, $rabbit_config)
      $schema_config_default_common =  {
        'api_server_ip'         => $api_server,
        'api_server_port'       => $api_port,
        'api_server_use_ssl'    => $internal_api_ssl,
        'cassandra_server_list' => $cassandra_server_list_9160,
        'collectors'            => $collector_server_list_8086,
        'rabbit_server'         => $rabbit_server_list_5672,
        'rabbit_user'           => $rabbit_user,
        'rabbit_password'       => $rabbit_password,
        'rabbit_use_ssl'        => $rabbit_use_ssl,
        'redis_server'          => $redis_server,
        'zk_server_ip'          => $zk_server_ip_2181,
      }
      $schema_config_default = deep_merge($schema_config_default_common, $rabbit_config)
      class {'::contrail::config':
        contrail_version      => $contrail_version,
        api_config            => {
          'DEFAULTS' => $api_config_default,
          'SANDESH'  => $sandesh_config,
        },
        config_nodemgr_config => {
          'COLLECTOR' => {
            'server_list'           => $collector_server_list_8086,
          },
          'SANDESH'   => $sandesh_config,
        },
        device_manager_config => {
          'DEFAULTS' => $device_manager_config_default,
          'SANDESH'  => $sandesh_config,
        },
        keystone_config       => $keystone_config,
        schema_config         => {
          'DEFAULTS' => $schema_config_default,
          'SANDESH'  => $sandesh_config,
        },
        svc_monitor_config    => {
          'DEFAULTS'  => $svc_monitor_config_default,
          'SCHEDULER' => {
            'analytics_server_list' => $analytics_server_list_8081,
          },
          'SANDESH'   => $sandesh_config,
        },
        vnc_api_lib_config    => $vnc_api_lib_config,
      }
    }
  }
  if $step >= 5 {
    class {'::contrail::config::provision_config':
      api_address                => $api_server,
      api_port                   => $api_port,
      api_server_use_ssl         => $internal_api_ssl,
      config_node_address        => $host_ip,
      config_node_name           => $::hostname,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
      openstack_vip              => $auth_host,
    }
    class {'::contrail::config::provision_alarm':
      api_address                => $api_server,
      api_port                   => $api_port,
      api_server_use_ssl         => $internal_api_ssl,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
    }
    if $config_hostnames[0] == $::hostname {
      class {'::contrail::config::provision_linklocal':
        api_address                => $api_server,
        api_port                   => $api_port,
        api_server_use_ssl         => $internal_api_ssl,
        ipfabric_service_ip        => $internal_vip,
        ipfabric_service_port      => $ipfabric_service_port,
        keystone_admin_user        => $admin_user,
        keystone_admin_password    => $admin_password,
        keystone_admin_tenant_name => $admin_tenant_name,
        linklocal_service_name     => $linklocal_service_name,
        linklocal_service_ip       => $linklocal_service_ip,
        linklocal_service_port     => $linklocal_service_port,
      }
    }
  }
}
