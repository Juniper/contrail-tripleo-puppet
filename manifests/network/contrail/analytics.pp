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
# == Class: tripleo::network::contrail::analytics
#
# Configure Contrail Analytics services
#
# == Parameters:
#
# [*host_ip*]
#  (required) host IP address of Analytics
#  String (IPv4) value.
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
# [*analytics_aaa_mode*]
#  (optional) analytics aaa mode parameter
#  String value.
#  Defaults to hiera('contrail::analytics_aaa_mode')
#
# [*analytics_server_list*]
#  (optional) list of analytics server
#  Array of String values.
#  Defaults to hiera('contrail_analytics_node_ips')
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
#  Defaults to hiera('contrail_analytics_database_node_ips')
#
# [*config_server_list*]
#  (optional) List IPs+port of Config servers
#  Array of strings value.
#  Defaults to hiera('contrail_config_node_ips')
#
# [*collector_http_server_port*]
#  (optional) Collector http port
#  Integer value.
#  Defaults to 8089
#
# [*collector_sandesh_port*]
#  (optional) Collector sandesh port
#  Integer value.
#  Defaults to 8086
#
# [*contrail_version*]
#  (optional) contrail version.
#  Integer value.
#  Defaults to hiera('contrail::contrail_version',4)
#
# [*disc_server_ip*]
#  (optional) IPv4 address of discovery server.
#  String (IPv4) value.
#  Defaults to hiera('contrail::disc_server_ip')
#
# [*disc_server_port*]
#  (optional) port Discovery server listens on.
#  Integer value.
#  Defaults to hiera('contrail::disc_server_port')
#
# [*http_server_port*]
#  (optional) Analytics http port
#  Integer value.
#  Defaults to 8090
#
# [*insecure*]
#  (optional) insecure mode.
#  Boolean value.
#  Defaults to falsehiera('contrail::insecure')
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
# [*kafka_broker_list*]
#  (optional) List IPs+port of kafka servers
#  Array of strings value.
#  Defaults to hiera('contrail::kafka_broker_list')
#
# [*memcached_servers*]
#  (optional) IPv4 address of memcached servers
#  String (IPv4) value + port
#  Defaults to hiera('contrail::memcached_server')
#
# [*internal_vip*]
#  (optional) Public virtual IP address
#  String (IPv4) value
#  Defaults to hiera('internal_api_virtual_ip')
#
# [*rabbit_server*]
#  (optional) IPv4 addresses of rabbit server.
#  Array of String (IPv4) value.
#  Defaults to hiera('rabbitmq_node_ips')
#
# [*rabbit_user*]
#  (optional) Rabbit user
#  String value.
#  Defaults to hiera('contrail::rabbit_user')
#
# [*rabbit_password*]
#  (optional) Rabbit password
#  String value.
#  Defaults to hiera('contrail::rabbit_password')
#
# [*rabbit_port*]
#  (optional) port of rabbit server
#  String value.
#  Defaults to hiera('contrail::rabbit_port')
#
# [*redis_server*]
#  (optional) IPv4 address of redis server.
#  String (IPv4) value.
#  Defaults to '127.0.0.1'.
#
# [*redis_server_port*]
#  (optional) port Redis server listens on.
#  Integer value.
#  Defaults to 6379
#
# [*rest_api_ip*]
#  (optional) IP address Analytics rest interface listens on
#  String (IPv4) value.
#  Defaults to '0.0.0.0'
#
# [*rest_api_port*]
#  (optional) Analytics rest port
#  Integer value.
#  Defaults to 8081
#
# [*step*]
#  (optional) Step stack is in
#  Integer value.
#  Defaults to hiera('step')
#
# [*zk_server_ip*]
#  (optional) List IPs+port of Zookeeper servers
#  Array of strings value.
#  Defaults to hiera('contrail::zk_server_ip')
#
class tripleo::network::contrail::analytics(
  $step                         = Integer(hiera('step')),
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
  $analytics_aaa_mode           = hiera('contrail::analytics_aaa_mode'),
  $analytics_server_list        = hiera('contrail_analytics_node_ips'),
  $cassandra_server_list        = hiera('contrail_analytics_database_node_ips'),
  $ssl_enabled                  = hiera('contrail_ssl_enabled', false),
  $internal_api_ssl             = hiera('contrail_internal_api_ssl', false),
  $ca_file                      = hiera('contrail::ca_cert_file', undef),
  $ca_cert                      = hiera('contrail::ca_cert', undef),
  $ca_key_file                  = hiera('contrail::ca_key_file', undef),
  $ca_key                       = hiera('contrail::ca_key', undef),
  $key_file                     = hiera('contrail::service_key_file', undef),
  $cert_file                    = hiera('contrail::service_cert_file', undef),
  $config_server_list           = hiera('contrail_config_node_ips'),
  $collector_http_server_port   = hiera('contrail::analytics::collector_http_server_port'),
  $collector_sandesh_port       = hiera('contrail::analytics::collector_sandesh_port'),
  $contrail_version             = hiera('contrail::contrail_version',4),
  $disc_server_ip               = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $disc_server_port             = hiera('contrail::disc_server_port'),
  $http_server_port             = hiera('contrail::analytics::http_server_port'),
  $host_ip                      = hiera('contrail::analytics::host_ip'),
  $insecure                     = hiera('contrail::insecure'),
  $kafka_broker_list            = hiera('contrail_analytics_database_node_ips'),
  $keystone_auth_type           = hiera('contrail::keystone_auth_type','password'),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $memcached_servers            = hiera('contrail::memcached_server'),
  $internal_vip                 = hiera('internal_api_virtual_ip'),
  $rabbit_server                = hiera('rabbitmq_node_ips'),
  $rabbit_user                  = hiera('contrail::rabbit_user'),
  $rabbit_password              = hiera('contrail::rabbit_password'),
  $rabbit_port                  = hiera('contrail::rabbit_port'),
  $rabbit_vhost                 = hiera('contrail::rabbit_vhost','/'),
  $rabbit_use_ssl               = hiera('contrail::rabbit_use_ssl', false),
  $rabbit_ca_file               = hiera('contrail::rabbit_ca_file', undef),
  $redis_server                 = hiera('contrail::analytics::redis_server'),
  $redis_server_port            = hiera('contrail::analytics::redis_server_port'),
  $rest_api_ip                  = hiera('contrail::analytics::rest_api_ip'),
  $rest_api_port                = hiera('contrail::analytics::rest_api_port'),
  $zk_server_ip                 = hiera('contrail_database_node_ips'),
)
{
  $cassandra_server_list_9042 = join([join($cassandra_server_list, ':9042 '),':9042'],'')
  $config_api_server_list_8082 = join([join($config_server_list, ':8082 '),':8082'],'')
  $collector_server_list_8086 = join([join($analytics_server_list, ':8086 '),':8086'],'')
  $config_db_server_list_9042 = join([join($config_server_list, ':9042 '),':9042'],'')
  $config_db_server_list_9160 = join([join($config_server_list, ':9160 '),':9160'],'')
  $redis_server_list_6379 = join([join($analytics_server_list, ':6379 '),':6379'],'')
  $kafka_broker_list_9092 = join([join($kafka_broker_list, ':9092 '),':9092'],'')
  $rabbit_server_list_5672 = join([join($rabbit_server, ':5672,'),':5672'],'')
  $rabbit_server_list_no_port = join($rabbit_server, ',')
  $redis_config = "bind ${host_ip} 127.0.0.1"
  $zk_server_ip_2181 = join([join($zk_server_ip, ':2181 '),':2181'],'')
  $zk_server_ip_2181_comma = join([join($zk_server_ip, ':2181,'),':2181'],'')
  if $auth_version == 2 {
    $keystone_config_ver = {}
    $auth_url_suffix = 'v2.0'
    $vnc_authn_url = '/v2.0/tokens'
  } else {
    $keystone_config_ver = {
      'auth_type'               => $keystone_auth_type,
      'project_domain_name'     => $keystone_project_domain_name,
      'user_domain_name'        => $keystone_user_domain_name,
    }
    $auth_url_suffix = 'v3'
    $vnc_authn_url = '/v3/auth/tokens'
  }
  $auth_url = "${auth_protocol}://${auth_host}:${auth_port}/${auth_url_suffix}"
  if $internal_api_ssl {
    if $auth_ca_file {
      $cafile_keystone = {
        'cafile' => $auth_ca_file,
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
        'admin_password'    => $admin_password,
        'admin_tenant_name' => $admin_tenant_name,
        'admin_user'        => $admin_user,
        'auth_host'         => $auth_host,
        'auth_port'         => $auth_port,
        'auth_protocol'     => $auth_protocol,
        'auth_url'          => $auth_url,
        'insecure'          => $insecure,
        'region_name'       => $keystone_region,
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
  $keystone_config = deep_merge($keystone_config_proto, $keystone_config_ver)
  $sandesh_config = {
    'introspect_ssl_enable' => $ssl_enabled,
    'sandesh_ssl_enable'    => $ssl_enabled,
    'sandesh_keyfile'       => $key_file,
    'sandesh_certfile'      => $cert_file,
    'sandesh_ca_cert'       => $ca_file,
  }
  if $step == 1 {
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
    }
  }
  if $rabbit_use_ssl {
    $rabbit_ssl_config = {
      'rabbitmq_use_ssl'     => $rabbit_use_ssl,
      'kombu_ssl_certfile'   => $cert_file,
      'kombu_ssl_keyfile'    => $key_file,
      'kombu_ssl_ca_certs'   => $rabbit_ca_file,
    }
  } else {
    $rabbit_ssl_config = {}
  }
  if $step >= 3 {
    if $contrail_version == 3 {
      class {'::contrail::analytics':
        contrail_version          => $contrail_version,
        alarm_gen_config          => {
          'DEFAULTS'  => {
            'host_ip'              => $host_ip,
            'kafka_broker_list'    => $kafka_broker_list_9092,
            'rabbitmq_server_list' => $rabbit_server_list_5672,
            'rabbitmq_user'        => $rabbit_user,
            'rabbitmq_password'    => $rabbit_password,
            'zk_list'              => $zk_server_ip_2181,
          },
          'DISCOVERY' => {
            'disc_server_ip'   => $disc_server_ip,
            'disc_server_port' => $disc_server_port,
          },
          'SANDESH'   => $sandesh_config,
        },
        analytics_nodemgr_config  => {
          'DISCOVERY' => {
            'server' => $disc_server_ip,
            'port'   => $disc_server_port,
          },
          'SANDESH'   => $sandesh_config,
        },
        analytics_api_config      => {
          'DEFAULTS'  => {
            'api_server'            => "${api_server}:${api_port}",
            'api_server_use_ssl'    => $internal_api_ssl,
            'aaa_mode'              => $analytics_aaa_mode,
            'cassandra_server_list' => $cassandra_server_list_9042,
            'host_ip'               => $host_ip,
            'http_server_port'      => $http_server_port,
            'rest_api_ip'           => $rest_api_ip,
            'rest_api_port'         => $rest_api_port,
          },
          'DISCOVERY' => {
            'disc_server_ip'   => $disc_server_ip,
            'disc_server_port' => $disc_server_port,
          },
          'REDIS'     => {
            'redis_server_port' => $redis_server_port,
            'redis_query_port'  => $redis_server_port,
            'server'            => $redis_server,
          },
          'KEYSTONE'  => $keystone_config,
          'SANDESH'   => $sandesh_config,
        },
        collector_config          => {
          'DEFAULT'   => {
            'cassandra_server_list' => $cassandra_server_list_9042,
            'hostip'                => $host_ip,
            'http_server_port'      => $collector_http_server_port,
            'kafka_broker_list'     => $kafka_broker_list_9092,
            'zookeeper_server_list' => $zk_server_ip_2181_comma,
          },
          'COLLECTOR' => {
            'port' => $collector_sandesh_port,
          },
          'DISCOVERY' => {
            'server' => $disc_server_ip,
            'port'   => $disc_server_port,
          },
          'REDIS'     => {
            'port'   => $redis_server_port,
            'server' => $redis_server,
          },
          'SANDESH'   => $sandesh_config,
        },
        query_engine_config       => {
          'DEFAULT'   => {
            'cassandra_server_list' => $cassandra_server_list_9042,
            'hostip'                => $host_ip,
          },
          'DISCOVERY' => {
            'server' => $disc_server_ip,
            'port'   => $disc_server_port,
          },
          'REDIS'     => {
            'port'   => $redis_server_port,
            'server' => $redis_server,
          },
        },
        snmp_collector_config     => {
          'DEFAULTS'  => {
            'zookeeper'  => $zk_server_ip_2181_comma,
          },
          'DISCOVERY' => {
            'disc_server_ip'   => $disc_server_ip,
            'disc_server_port' => $disc_server_port,
          },
          'KEYSTONE'  => $keystone_config,
          'SANDESH'   => $sandesh_config,
        },
        redis_config              => $redis_config,
        topology_config           => {
          'DEFAULTS'  => {
            'zookeeper'  => $zk_server_ip_2181_comma,
          },
          'DISCOVERY' => {
            'disc_server_ip'   => $disc_server_ip,
            'disc_server_port' => $disc_server_port,
          },
          'SANDESH'   => $sandesh_config,
        },
        vnc_api_lib_config        => $vnc_api_lib_config,
        keystone_config           => {
          'KEYSTONE'     => $keystone_config,
        },
        rabbitmq_server_list      => $rabbit_server_list_no_port,
        rabbitmq_port             => '5672',
        rabbitmq_vhost            => $rabbit_vhost,
        rabbitmq_user             => $rabbit_user,
        rabbitmq_password         => $rabbit_password,
        rabbit_ssl_config         => $rabbit_ssl_config,
        config_db_cql_server_list => $config_db_server_list_9042,
        config_db_server_list     => $config_db_server_list_9160,
      }
    } else {
      class {'::contrail::analytics':
        contrail_version          => $contrail_version,
        alarm_gen_config          => {
          'DEFAULTS'   => {
            'collectors'        => $collector_server_list_8086,
            'host_ip'           => $host_ip,
            'kafka_broker_list' => $kafka_broker_list_9092,
            'zk_list'           => $zk_server_ip_2181,
          },
          'API_SERVER' => {
            'api_server_list' => $config_api_server_list_8082,
          },
          'REDIS'      => {
            'redis_server_port' => $redis_server_port,
            'redis_query_port'  => $redis_server_port,
            'server'            => $redis_server,
            'redis_uve_list'    => $redis_server_list_6379,
          },
          'SANDESH'    => $sandesh_config,
        },
        analytics_nodemgr_config  => {
          'COLLECTOR' => {
            'server_list'   => $collector_server_list_8086,
          },
          'SANDESH'   => $sandesh_config,
        },
        analytics_api_config      => {
          'DEFAULTS' => {
            'api_server'            => $config_api_server_list_8082,
            'aaa_mode'              => $analytics_aaa_mode,
            'cassandra_server_list' => $cassandra_server_list_9042,
            'collectors'            => $collector_server_list_8086,
            'host_ip'               => $host_ip,
            'http_server_port'      => $http_server_port,
            'rest_api_ip'           => $rest_api_ip,
            'rest_api_port'         => $rest_api_port,
            'zk_list'               => $zk_server_ip_2181,
          },
          'REDIS'    => {
            'redis_server_port' => $redis_server_port,
            'redis_query_port'  => $redis_server_port,
            'server'            => $redis_server,
            'redis_uve_list'    => $redis_server_list_6379,
          },
          'KEYSTONE' => $keystone_config,
          'SANDESH'  => $sandesh_config,
        },
        collector_config          => {
          'DEFAULT'                     => {
            'cassandra_server_list' => $cassandra_server_list_9042,
            'hostip'                => $host_ip,
            'http_server_port'      => $collector_http_server_port,
            'kafka_broker_list'     => $kafka_broker_list_9092,
            'zookeeper_server_list' => $zk_server_ip_2181_comma,
          },
          'API_SERVER'                  => {
            'api_server_list' => $config_api_server_list_8082,
          },
          'COLLECTOR'                   => {
            'port' => $collector_sandesh_port,
          },
          'STRUCTURED_SYSLOG_COLLECTOR' => {
            'kafka_broker_list' => $kafka_broker_list_9092,
          },
          'REDIS'                       => {
            'port'   => $redis_server_port,
            'server' => $redis_server,
          },
          'SANDESH'                     => $sandesh_config,
        },
        query_engine_config       => {
          'DEFAULT' => {
            'collectors'            => $collector_server_list_8086,
            'cassandra_server_list' => $cassandra_server_list_9042,
            'hostip'                => $host_ip,
          },
          'REDIS'   => {
            'port'   => $redis_server_port,
            'server' => $redis_server,
          },
          'SANDESH' => $sandesh_config,
        },
        snmp_collector_config     => {
          'DEFAULTS'   => {
            'collectors' => $collector_server_list_8086,
            'zookeeper'  => $zk_server_ip_2181_comma,
          },
          'KEYSTONE'   => $keystone_config,
          'API_SERVER' => {
            'api_server_list' => $config_api_server_list_8082,
          },
          'SANDESH'    => $sandesh_config,
        },
        redis_config              => $redis_config,
        topology_config           => {
          'DEFAULTS'   => {
            'collectors' => $collector_server_list_8086,
            'zookeeper'  => $zk_server_ip_2181_comma,
          },
          'API_SERVER' => {
            'api_server_list' => $config_api_server_list_8082,
          },
          'SANDESH'    => $sandesh_config,
        },
        vnc_api_lib_config        => $vnc_api_lib_config,
        keystone_config           => {
          'KEYSTONE'     => $keystone_config,
        },
        rabbitmq_server_list      => $rabbit_server_list_no_port,
        rabbitmq_port             => '5672',
        rabbitmq_vhost            => $rabbit_vhost,
        rabbitmq_user             => $rabbit_user,
        rabbitmq_password         => $rabbit_password,
        rabbit_ssl_config         => $rabbit_ssl_config,
        config_db_cql_server_list => $config_db_server_list_9042,
        config_db_server_list     => $config_db_server_list_9160,
      }
    }
  }
  if $step >= 5 {
    class {'::contrail::analytics::provision_analytics':
      api_address                => $api_server,
      api_port                   => $api_port,
      api_server_use_ssl         => $internal_api_ssl,
      analytics_node_address     => $host_ip,
      analytics_node_name        => $::fqdn,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
      openstack_vip              => $auth_host,
    }
  }
}
