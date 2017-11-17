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
# == Class: tripleo::network::contrail::analyticsdatabase
#
# Configure Contrail Analytics Database services
#
# == Parameters:
#
# [*analytics_server_list*]
#  (optional) list of analytics server
#  Array of String values.
#  Defaults to hiera('contrail_analytics_node_ips')
#
# [*auth_host*]
#  (optional) IPv4 VIP of Keystone
#  String (IPv4) value
#  Defaults to hiera('contrail::auth_host')
#
# [*auth_protocol*]
#  (optional) authentication protocol.
#  String value.
#  Defaults to hiera('contrail::auth_protocol')
#
# [*api_server*]
#  (optional) IPv4 VIP of Contrail Config API
#  String (IPv4) value
#  Defaults to hiera('contrail_config_vip',hiera('internal_api_virtual_ip'))
#
# [*api_port*]
#  (optional) Port of Contrail Config API
#  String value
#  Defaults to hiera('contrail::api_port')
#
# [*admin_password*]
#  (optional) Keystone Admin password
#  String value
#  Defaults to hiera('contrail::admin_password')
#
# [*admin_tenant_name*]
#  (optional) Keystone Admin tenant name
#  String value
#  Defaults to hiera('contrail::admin_tenant_name')
#
# [*admin_token*]
#  (optional) Keystone Admin token
#  String value
#  Defaults to hiera('contrail::admin_token')
#
# [*admin_user*]
#  (optional) Keystone Admin user
#  String value
#  Defaults to hiera('contrail::admin_user')
#
# [*analytics_server_list*]
#  (optional) list of analytics server
#  Array of String values.
#  Defaults to hiera('contrail_analytics_node_ips')
#
# [*analyticsdb_min_disk_gb*]
#  (optional) min size for Contrail Analytics DB.
#  Integer value.
#  Defaults to hiera('contrail_analyticsdb_min_disk_gb')
#
# [*contrail_version*]
#  (optional) contrail version.
#  Integer value.
#  Defaults to hiera('contrail::contrail_version',4)
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
# [*cassandra_servers*]
#  (optional) List of analytics cassandra servers
#  List (IPv4) value
#  Defaults to hiera('contrail_analytics_database_node_ips')
#
# [*disc_server_ip*]
#  (optional) IPv4 VIP of Contrail Discovery
#  String (IPv4) value
#  Defaults to hiera('contrail_config_vip',hiera('internal_api_virtual_ip'))
#
# [*disc_server_port*]
#  (optional) port Discovery server listens on.
#  Integer value.
#  Defaults to hiera('contrail::disc_server_port')
#
# [*host_ip*]
#  (optional) host IP address of Database node
#  String (IPv4) value.
#  Defaults to hiera('contrail::analytics::database::host_ip')
#
# [*host_name*]
#  (optional) host name of database node
#  String value
#  Defaults to $::hostname
#
# [*kafka_hostnames*]
#  (optional) list of kafka server hostnames
#  List value
#  Defaults to hiera('contrail_analytics_database_short_node_names', '')
#
# [*internal_vip*]
#  (optional) Public VIP
#  String (IPv4) value
#  Defaults to hiera('internal_api_virtual_ip')
#
# [*step*]
#  (optional) step in the stack
#  String value
#  Defaults to hiera('step')
#
# [*zookeeper_server_ips*]
#  (optional) list of zookeeper server IPs
#  List value
#  Defaults to hiera('contrail_database_node_ips')
#
class tripleo::network::contrail::analyticsdatabase(
  $step                     = Integer(hiera('step')),
  $analytics_server_list    = hiera('contrail_analytics_node_ips'),
  $auth_host                = hiera('contrail::auth_host'),
  $api_server               = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $api_port                 = hiera('contrail::api_port'),
  $admin_password           = hiera('contrail::admin_password'),
  $admin_tenant_name        = hiera('contrail::admin_tenant_name'),
  $admin_token              = hiera('contrail::admin_token'),
  $admin_user               = hiera('contrail::admin_user'),
  $auth_port                = hiera('contrail::auth_port'),
  $auth_protocol            = hiera('contrail::auth_protocol'),
  $cassandra_servers        = hiera('contrail_analytics_database_node_ips'),
  $ca_file                  = hiera('contrail::service_certificate',false),
  $cert_file                = hiera('contrail::service_certificate',false),
  $analyticsdb_min_disk_gb  = hiera('contrail_analyticsdb_min_disk_gb',undef),
  $contrail_version         = hiera('contrail::contrail_version',4),
  $disc_server_ip           = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $disc_server_port         = hiera('contrail::disc_server_port'),
  $host_ip                  = hiera('contrail::analytics::database::host_ip'),
  $host_name                = $::hostname,
  $kafka_hostnames          = hiera('contrail_analytics_database_short_node_names', ''),
  $internal_vip             = hiera('internal_api_virtual_ip'),
  $zookeeper_server_ips     = hiera('contrail_database_node_ips'),
)
{
  $collector_server_list_8086 = join([join($analytics_server_list, ':8086 '),':8086'],'')
  if $auth_protocol == 'https' {
    $vnc_api_lib_config = {
      'auth' => {
        'AUTHN_SERVER'   => $auth_host,
        'AUTHN_PORT'     => $auth_port,
        'AUTHN_PROTOCOL' => $auth_protocol,
        'certfile'       => $cert_file,
        'cafile'         => $ca_file,
      },
    }
  } else {
    $vnc_api_lib_config = {
      'auth' => {
        'AUTHN_SERVER' => $auth_host,
      },
    }
  }
  if $step == 2 {
    if $contrail_version == 3 {
      $nodemgr_default_name = 'DEFAULT'
      $nodemgr_ver_specific = {
        'DISCOVERY' => {
          'server'   => $disc_server_ip,
          'port'     => $disc_server_port,
        },
      }
    } else {
      $nodemgr_default_name = 'DEFAULTS'
      $nodemgr_ver_specific = {
        'COLLECTOR' => {
          'server_list' => $collector_server_list_8086,
        },
      }
    }
    $nodemgr_default = $analyticsdb_min_disk_gb ? {
      undef   => {
        "${nodemgr_default_name}" => {
          'hostip'          => $host_ip,
        },
      },
      default => {
        "${nodemgr_default_name}" => {
          'hostip'          => $host_ip,
          'minimum_diskGB'  => $analyticsdb_min_disk_gb,
        },
      }
    }
    $nodemgr_config = deep_merge($nodemgr_default, $nodemgr_ver_specific)
    class {'::contrail::analyticsdatabase':
      analyticsdatabase_params => {
        'auth_host'             => $auth_host,
        'api_server'            => $api_server,
        'admin_password'        => $admin_password,
        'admin_tenant_name'     => $admin_tenant_name,
        'admin_user'            => $admin_user,
        'cassandra_servers'     => $cassandra_servers,
        'host_ip'               => $host_ip,
        'disc_server_ip'        => $disc_server_ip,
        'disc_server_port'      => $disc_server_port,
        'kafka_hostnames'       => $kafka_hostnames,
        'zookeeper_server_ips'  => $zookeeper_server_ips,
        database_nodemgr_config => $nodemgr_config,
        vnc_api_lib_config      => $vnc_api_lib_config,
      }
    }
  }
  if $step >= 5 {
    class {'::contrail::database::provision_database':
      api_address                => $api_server,
      api_port                   => $api_port,
      database_node_address      => $host_ip,
      database_node_name         => $host_name,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
      openstack_vip              => $auth_host,
    }
  }
}
