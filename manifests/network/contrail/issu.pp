
# Contrail ISSU
#

class tripleo::network::contrail::issu(
  $step                         = hiera('step'),
  $admin_tenant_name            = hiera('contrail::admin_tenant_name'),
  $admin_user                   = hiera('contrail::admin_user'),
  $admin_password               = hiera('contrail::admin_password'),
  $api_server                   = hiera('contrail_config_vip', hiera('internal_api_virtual_ip')),
  $api_port                     = 8082,
  $cassandra_server_list        = hiera('contrail_database_node_ips'),
  $old_config_servers           = hiera('contrail_config_node_ips'),
  $old_control_servers          = hiera('contrail::vrouter::control_node_ips', hiera('contrail_control_node_ips')),
  $old_analytics_servers        = hiera('contrail_analytics_node_ips'),
  $old_analyticsdb_servers      = hiera('contrail_analytics_database_node_ips'),
  $container_registry           = hiera('contrail_issu_container_registry'),
  $container_tag                = hiera('contrail_issu_container_tag'),
  $host_ip                      = hiera('contrail_issu_host_ip'),
  $ibgp_auto_mesh               = true,
  $issu_ips                     = hiera('contrail_issu_node_ips'),
  $issu_ssh_user                = hiera('contrail_issu_ssh_user'),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $metadata_secret              = hiera('contrail::vrouter::metadata_proxy_shared_secret'),
  $metadata_host_ip             = hiera('internal_api_virtual_ip'),
  $rabbit_password              = hiera('contrail::rabbit_password'),
  $rabbit_port                  = hiera('contrail::rabbit_port'),
  $rabbit_server                = hiera('rabbitmq_node_ips'),
  $rabbit_user                  = hiera('contrail::rabbit_user'),
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

  $old_cassandra_server_list_9160 = join([join($cassandra_server_list, ':9160 '),':9160'],'')
  $old_cassandra_server_list_9161 = join([join($cassandra_server_list, ':9161 '),':9161'],'')

  $old_zk_server_ip_2181 = join([join($zk_server_ip, ':2181,'),':2181'],'')
  $old_rabbit_server_list_5672 = join([join($rabbit_server, ':5672,'),':5672'],'')
  $old_rabbit_server_list = join($rabbit_server, ',')
  # at revert step old should point to Contrail Config Database 
  # because 5.x Contrail has own rabbit
  $revert_issu_old_rabbit_server_list = join($zk_server_ip, ',')

  $issu_api_info = "{\"${host_ip}\": [(\"${issu_ssh_user}\"), (\"\")]}"
  $revert_issu_api_info = join(['{"', join([join($old_config_servers, "\": [(\"${issu_ssh_user}\"), (\"\")],\"", ''), "\": [(\"${issu_ssh_user}\"), (\"\")]}"], '')], '')

  $first_old_config_server_ip = $old_config_servers[0]
  $old_config_servers_list_space = join($old_config_servers, ' ')
  $old_control_servers_list_space = join($old_control_servers, ' ')

  $old_analytics_servers_list_space = join($old_analytics_servers, ' ')
  $old_analyticsdb_servers_list_space = join($old_analyticsdb_servers, ' ')

  $issu_ips_list_space = join($issu_ips, ' ')
  $issu_ips_list_comma = join($issu_ips, ',')

  $issu_instances = {
    "$::hostname" => "$host_ip",
  }

  $issu_dir='/etc/contrail/issu'

  exec { 'set selinux to permissive' :
    command => 'setenforce permissive',
    path    => '/bin:/sbin:/usr/bin:/usr/sbin',
    onlyif  => 'sestatus | grep -i "Current mode" | grep -q enforcing',
  } ->
  file_line { 'make permissive mode persistant':
    ensure => present,
    path   => '/etc/selinux/config',
    line   => 'SELINUX=permissive',
    match  => '^SELINUX=',
  } ->
  file { '/etc/contrail' :
    ensure  => directory,
  } ->
  file { $issu_dir :
    ensure  => directory,
  } ->
  file { "${issu_dir}/issu.conf" :
    ensure  => file,
    content => template('tripleo/contrail/issu.conf.erb'),
    mode    => 644,
  } ->
  file { "${issu_dir}/issu_revert.conf" :
    ensure  => file,
    content => template('tripleo/contrail/issu_revert.conf.erb'),
    mode    => 644,
  } ->
  file { "${issu_dir}/issu.env" :
    ensure  => file,
    content => template("tripleo/contrail/issu.env.erb"),
  } ->
  file { "${issu_dir}/issu_node_deploy.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_deploy.sh.erb'),
    mode    => 755,
  } ->
  file { "${issu_dir}/issu_node_pair.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_pair.sh.erb'),
    mode    => 755,
  } ->
  file { "${issu_dir}/issu_node_sync.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_sync.sh.erb'),
    mode    => 755,
  } ->
  file { "${issu_dir}/instances_issu.yaml" :
    ensure  => file,
    content => template('tripleo/contrail/instances_common.yaml.erb', 'tripleo/contrail/instances_issu.yaml.erb'),
    mode    => 644,
  }
}
