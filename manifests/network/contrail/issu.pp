
# Contrail ISSU
#

class tripleo::network::contrail::issu(
  $step                         = hiera('step'),
  $aaa_mode                     = hiera('contrail::aaa_mode'),
  $auth_host                    = hiera('contrail::auth_host'),
  $auth_protocol                = hiera('contrail::auth_protocol'),
  $auth_version                 = hiera('contrail::auth_version',2),
  $admin_tenant_name            = hiera('contrail::admin_tenant_name'),
  $admin_user                   = hiera('contrail::admin_user'),
  $admin_password               = hiera('contrail::admin_password'),
  $api_server                   = hiera('contrail_config_vip', hiera('internal_api_virtual_ip')),
  $api_port                     = 8082,
  $cassandra_server_list        = hiera('contrail_database_node_ips'),
  $config_servers               = hiera('contrail_config_node_ips'),
  $control_servers              = hiera('contrail::vrouter::control_node_ips', hiera('contrail_control_node_ips')),
  $container_registry           = hiera('contrail_issu_container_registry'),
  $container_tag                = hiera('contrail_issu_container_tag'),
  $host_ip                      = hiera('contrail_issu_host_ip'),
  $host_ip_control              = hiera('contrail_issu_host_ip_control', hiera('contrail_issu_host_ip')),
  $ibgp_auto_mesh               = true,
  $issu_ips                     = hiera('contrail_issu_node_ips', undef),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $metadata_secret              = hiera('contrail::vrouter::metadata_proxy_shared_secret'),
  $metadata_host_ip             = hiera('internal_api_virtual_ip'),
  $rabbit_password              = hiera('contrail::rabbit_password'),
  $rabbit_port                  = hiera('contrail::rabbit_port'),
  $rabbit_server                = hiera('rabbitmq_node_ips'),
  $rabbit_user                  = hiera('contrail::rabbit_user'),
  $router_asn                   = hiera('contrail::control::asn'),
  $ssl_enabled                  = hiera('contrail_ssl_enabled', false),
  $zk_server_ip                 = hiera('contrail_database_node_ips'),
) {

  File {
    mode  => 644,
  }

  Exec {
    path => [ '/bin', '/usr/bin' ],
  }

  if $ssl_enabled {
    $use_ssl = 'True'
  } else {
    $use_ssl = 'False'
  }

  if $auth_version == 2 {
    $auth_version_str = '/v2.0'
  } else {
    $auth_version_str = '/v3'
  }

  $old_cassandra_server_list_9160 = join([join($cassandra_server_list, ':9160 '),':9160'],'')
  $old_cassandra_server_list_9161 = join([join($cassandra_server_list, ':9161 '),':9161'],'')

  $old_zk_server_ip_2181 = join([join($zk_server_ip, ':2181,'),':2181'],'')
  $old_rabbit_server_list_5672 = join([join($rabbit_server, ':5672,'),':5672'],'')
  $old_rabbit_server_list = join($rabbit_server, ',')
  
  $issu_api_info = "{\"${host_ip}\": [(\"root\"), (\"\")]}"
  $revert_issu_api_info = join(['{"', join([join($config_servers, '": [("root"), ("")],"', ''), '": [("root"), ("")]}'], '')], '')

  $config_servers_list_space = join($config_servers, ' ')

  $control_servers_list_space = join($control_servers, ' ')
  if $issu_ips {
    $issu_ips_list_space = join($issu_ips, ' ')
    $issu_ips_list_comma = join($issu_ips, ',')
  } else {
    $issu_ips_list_space = $host_ip
    $issu_ips_list_comma = $host_ip
  }
  
  $issu_control_servers_list_comma = $host_ip_control
  $issu_instances = {
    "$::hostname" => "$host_ip",
  }

  $issu_dir='/etc/contrail/issu'
  file { '/etc/contrail' :
    ensure  => directory,
  } ->
  file { $issu_dir :
    ensure  => directory,
  } ->
  file { "${issu_dir}/issu.conf" :
    ensure  => file,
    content => template('tripleo/contrail/issu.conf.erb'),
  } ->
  file { "${issu_dir}/issu_revert.conf" :
    ensure  => file,
    content => template('tripleo/contrail/issu_revert.conf.erb'),
  } ->
  file { "${issu_dir}/issu_node_deploy.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_deploy.sh.erb'),
    mode    => 744,
  } ->
  file { "${issu_dir}/issu_node_provision.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_provision.sh.erb'),
    mode    => 744,
  } ->
  file { "${issu_dir}/instances_issu.yaml" :
    ensure  => file,
    content => template('tripleo/contrail/instances_common.yaml.erb', 'tripleo/contrail/instances_issu.yaml.erb'),
  }
  #  ->
  # exec { 'start issu' :
  #   command => "${issu_dir}/issu_node_deploy.sh",
  # }
}
