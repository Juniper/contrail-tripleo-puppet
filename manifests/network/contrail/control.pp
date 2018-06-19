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
# == Class: tripleo::network::contrail::control
#
# Configure Contrail Control services
#
# == Parameters:
#
# [*admin_password*]
#  (optional) admin password
#  String value.
#  Defaults to hiera('contrail::admin_password'),
#
# [*admin_tenant_name*]
#  (optional) admin tenant name.
#  String value.
#  Defaults to hiera('contrail::admin_tenant_name'),
#
# [*admin_token*]
#  (optional) admin token
#  String value.
#  Defaults to hiera('contrail::admin_token'),
#
# [*admin_user*]
#  (optional) admin user name.
#  String value.
#  Defaults to hiera('contrail::admin_user'),
#
# [*analytics_server_list*]
#  (optional) list of analytics server
#  Array of String values.
#  Defaults to hiera('contrail_analytics_node_ips')
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
#  Defaults to hiera('contrail::auth_host'),
#
# [*auth_port*]
#  (optional) keystone port.
#  Defaults to hiera('contrail::auth_port'),
#
# [*auth_protocol*]
#  (optional) authentication protocol.
#  Defaults to hiera('contrail::auth_protocol'),
#
# [*config_server_list*]
#  (optional) List IPs+port of Config servers
#  Array of strings value.
#  Defaults to hiera('contrail_config_node_ips')
#
# [*contrail_version*]
#  (optional) contrail version.
#  Integer value.
#  Defaults to hiera('contrail::contrail_version',4)
#
# [*disc_server_ip*]
#  (optional) IPv4 address of discovery server.
#  String (IPv4) value.
#  Defaults to hiera('contrail::disc_server_ip'),
#
# [*disc_server_port*]
#  (optional) port Discovery server listens on.
#  Integer value.
#  Defaults to hiera('contrail::disc_server_port'),
#
# [*host_ip*]
#  (optional) IP address of host
#  String (IPv4) value.
#  Defaults to hiera('contrail::control::host_ip')
#
# [*ibgp_auto_mesh*]
#  (optional) iBPG auto mesh
#  String value.
#  Defaults to true
#
# [*ifmap_password*]
#  (optional) ifmap password
#  String value.
#  Defaults to hiera('contrail::ifmap_password'),
#
# [*ifmap_username*]
#  (optional) ifmap username
#  String value.
#  Defaults to hiera('contrail::ifmap_username'),
#
# [*insecure*]
#  (optional) insecure mode.
#  Defaults to hiera('contrail::insecure'),
#
# [*manage_named*]
#  (optional) switch for managing named
#  String
#  Defaults to hiera('contrail::manage_named'),
#
# [*internal_vip*]
#  (optional) Public Virtual IP address
#  String (IPv4) value
#  Defaults to hiera('internal_api_virtual_ip')
#
# [*rabbit_server*]
#  (optional) IPv4 addresses of rabbit server.
#  Array of String (IPv4) value.
#  Defaults to hiera('rabbitmq_node_ips')
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
# [*rabbit_user*]
#  (optional) Rabbit user
#  String value.
#  Defaults to hiera('contrail::rabbit_user')
#
# [*router_asn*]
#  (optional) Autonomus System Number
#  String value
#  Defaults to hiera('contrail::control::asn')
#
# [*md5*]
#  (optional) Md5 config for the node
#  String value
#  Defaults to hiera('contrail::control::md5')
#
# [*secret*]
#  (optional) RNDC secret for named
#  String value
#  Defaults to hiera('contrail::control::rndc_secret')
#
# [*ssl_enabled*]
#  (optional) SSL should be used in internal Contrail services communications
#  Boolean value
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
# [*step*]
#  (optional) Step stack is in
#  Integer value.
#  Defaults to hiera('step')
#
class tripleo::network::contrail::control(
  $step                  = Integer(hiera('step')),
  $admin_password        = hiera('contrail::admin_password'),
  $admin_tenant_name     = hiera('contrail::admin_tenant_name'),
  $admin_token           = hiera('contrail::admin_token'),
  $admin_user            = hiera('contrail::admin_user'),
  $analytics_server_list = hiera('contrail_analytics_node_ips'),
  $api_server            = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $api_port              = hiera('contrail::api_port'),
  $auth_host             = hiera('contrail::auth_host'),
  $auth_port             = hiera('contrail::auth_port'),
  $auth_protocol         = hiera('contrail::auth_protocol'),
  $config_server_list    = hiera('contrail_config_node_ips'),
  $contrail_version      = hiera('contrail::contrail_version',4),
  $disc_server_ip        = hiera('contrail_config_vip',hiera('internal_api_virtual_ip')),
  $disc_server_port      = hiera('contrail::disc_server_port'),
  $encap_priority        = hiera('contrail::control::encap_priority', 'MPLSoUDP,MPLSoGRE,VXLAN'),
  $host_ip               = hiera('contrail::control::host_ip'),
  $ibgp_auto_mesh        = true,
  $ifmap_password        = hiera('contrail::control::host_ip'),
  $ifmap_username        = hiera('contrail::control::host_ip'),
  $insecure              = hiera('contrail::insecure'),
  $internal_vip          = hiera('internal_api_virtual_ip'),
  $rabbit_server         = hiera('rabbitmq_node_ips'),
  $rabbit_user           = hiera('contrail::rabbit_user'),
  $rabbit_password       = hiera('contrail::rabbit_password'),
  $rabbit_port           = hiera('contrail::rabbit_port'),
  $rabbit_use_ssl        = hiera('contrail::rabbit_use_ssl', false),
  $rabbit_ca_file        = hiera('contrail::rabbit_ca_file', undef),
  $router_asn            = hiera('contrail::control::asn'),
  $md5                   = hiera('contrail::control::md5', undef),
  $secret                = hiera('contrail::control::rndc_secret'),
  $manage_named          = hiera('contrail::control::manage_named'),
  $vxlan_vn_id_mode      = hiera('contrail::control::vxlan_vn_id_mode', undef),
  $ssl_enabled           = hiera('contrail_ssl_enabled', false),
  $internal_api_ssl      = hiera('contrail_internal_api_ssl', false),
  $ca_file               = hiera('contrail::ca_cert_file', undef),
  $key_file              = hiera('contrail::service_key_file', undef),
  $cert_file             = hiera('contrail::service_cert_file', undef),
)
{
  $control_ifmap_user     = "${ifmap_username}.control"
  $control_ifmap_password = "${ifmap_username}.control"
  $dns_ifmap_user         = "${ifmap_username}.dns"
  $dns_ifmap_password     = "${ifmap_username}.dns"
  $collector_server_list_8086 = join([join($analytics_server_list, ':8086 '),':8086'],'')
  $config_db_server_list_9042 = join([join($config_server_list, ':9042 '),':9042'],'')
  $rabbit_server_list_5672 = join([join($rabbit_server, ':5672 '),':5672'],'')
  $sandesh_config = {
    'introspect_ssl_enable' => $ssl_enabled,
    'sandesh_ssl_enable'    => $ssl_enabled,
    'sandesh_keyfile'       => $key_file,
    'sandesh_certfile'      => $cert_file,
    'sandesh_ca_cert'       => $ca_file,
  }
  if $step >= 3 {
    if $contrail_version == 3 {
      class {'::contrail::control':
        contrail_version       => $contrail_version,
        secret                 => $secret,
        manage_named           => $manage_named,
        control_config         => {
          'DEFAULT'   => {
            'hostip'           => $host_ip,
            'xmpp_auth_enable' => $ssl_enabled,
            'xmpp_ca_cert'     => $ca_file,
            'xmpp_server_key'  => $key_file,
            'xmpp_server_cert' => $cert_file,
          },
          'DISCOVERY' => {
            'port'   => $disc_server_port,
            'server' => $disc_server_ip,
          },
          'IFMAP'     => {
            'password' => $control_ifmap_user,
            'user'     => $control_ifmap_password,
          },
        },
        dns_config             => {
          'DEFAULT'   => {
            'hostip'               => $host_ip,
            'rndc_secret'          => $secret,
            'xmpp_dns_auth_enable' => $ssl_enabled,
            'xmpp_ca_cert'         => $ca_file,
            'xmpp_server_key'      => $key_file,
            'xmpp_server_cert'     => $cert_file,
          },
          'DISCOVERY' => {
            'port'   => $disc_server_port,
            'server' => $disc_server_ip,
          },
          'IFMAP'     => {
            'password' => $dns_ifmap_user,
            'user'     => $dns_ifmap_password,
          },
        },
        control_nodemgr_config => {
          'DISCOVERY' => {
            'server' => $disc_server_ip,
            'port'   => $disc_server_port,
          },
          'SANDESH'   => $sandesh_config,
        }
      }
    } else {
      if $rabbit_use_ssl {
        $rabbit_config = {
          'rabbitmq_ssl_certfile' => $cert_file,
          'rabbitmq_ssl_keyfile'  => $key_file,
          'rabbitmq_ssl_ca_certs' => $rabbit_ca_file,
        }
      } else {
        $rabbit_config = {}
      }
      $configdb_common =  {
        'rabbitmq_server_list'  => $rabbit_server_list_5672,
        'rabbitmq_user'         => $rabbit_user,
        'rabbitmq_password'     => $rabbit_password,
        'rabbitmq_vhost'        => '/',
        'rabbitmq_use_ssl'      => $rabbit_use_ssl,
        'config_db_server_list' => $config_db_server_list_9042,
      }
      $configdb_config = deep_merge($configdb_common, $rabbit_config)
      class {'::contrail::control':
        contrail_version       => $contrail_version,
        secret                 => $secret,
        manage_named           => $manage_named,
        control_config         => {
          'DEFAULT'  => {
            'hostip'           => $host_ip,
            'collectors'       => $collector_server_list_8086,
            'xmpp_auth_enable' => $ssl_enabled,
            'xmpp_ca_cert'     => $ca_file,
            'xmpp_server_key'  => $key_file,
            'xmpp_server_cert' => $cert_file,
          },
          'CONFIGDB' => $configdb_config,
          'SANDESH'  => $sandesh_config,
        },
        dns_config             => {
          'DEFAULT'  => {
            'hostip'               => $host_ip,
            'rndc_secret'          => $secret,
            'collectors'           => $collector_server_list_8086,
            'xmpp_dns_auth_enable' => $ssl_enabled,
            'xmpp_ca_cert'         => $ca_file,
            'xmpp_server_key'      => $key_file,
            'xmpp_server_cert'     => $cert_file,
          },
          'CONFIGDB' => $configdb_config,
          'SANDESH'  => $sandesh_config,
        },
        control_nodemgr_config => {
          'COLLECTOR' => {
            'server_list'   => $collector_server_list_8086,
          },
          'SANDESH'   => $sandesh_config,
        },
      }
    }
  }
  if $step >= 5 {
    class {'::contrail::control::provision_control':
      api_address                => $api_server,
      api_port                   => $api_port,
      api_server_use_ssl         => $internal_api_ssl,
      control_node_address       => $host_ip,
      control_node_name          => $::hostname,
      ibgp_auto_mesh             => $ibgp_auto_mesh,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
      router_asn                 => $router_asn,
      md5                        => $md5,
    } ->
    class {'::contrail::control::provision_encap':
      api_address                => $api_server,
      api_port                   => $api_port,
      api_server_use_ssl         => $internal_api_ssl,
      encap_priority             => $encap_priority,
      vxlan_vn_id_mode           => $vxlan_vn_id_mode,
      keystone_admin_user        => $admin_user,
      keystone_admin_password    => $admin_password,
      keystone_admin_tenant_name => $admin_tenant_name,
    }
  }
}
