
# Contrail ISSU
#

class tripleo::network::contrail::issu(
  $step                   = hiera('step'),
  $auth_host              = hiera('contrail::auth_host'),
  $admin_tenant_name      = hiera('contrail::admin_tenant_name'),
  $admin_user             = hiera('contrail::admin_user'),
  $admin_password         = hiera('contrail::admin_password'),
  $api_server             = hiera('contrail_config_vip', hiera('internal_api_virtual_ip')),
  $api_port               = 8082,
  $cassandra_server_list  = hiera('contrail_database_node_ips'),
  $control_server         = hiera('contrail_control_node_ips'),
  $host_ip                = hiera('contrail::issu::host_ip'),
  $ibgp_auto_mesh         = true,
  $issu_ips               = hiera('contrail_issu_node_ips', undef),
  $rabbit_password        = hiera('contrail::rabbit_password'),
  $rabbit_port            = hiera('contrail::rabbit_port'),
  $rabbit_server          = hiera('rabbitmq_node_ips'),
  $rabbit_user            = hiera('contrail::rabbit_user'),
  $router_asn             = hiera('contrail::control::asn'),
  $ssl_enabled            = hiera('contrail_ssl_enabled', false),
  $zk_server_ip           = hiera('contrail_database_node_ips'),
) {
  if $ssl_enabled {
    $use_ssl = 'True'
  } else {
    $use_ssl = 'False'
  }

  $old_cassandra_server_list_9160 = join([join($cassandra_server_list, ':9160 '),':9160'],'')
  $old_zk_server_ip_2181 = join([join($zk_server_ip, ':2181,'),':2181'],'')
  $old_rabbit_server_list_5672 = join([join($rabbit_server, ':5672,'),':5672'],'')

  $control_server_list_space = join($control_server, ' ')
  $issu_ips_list_space = join($issu_ips, ' ')
  
  file { '/etc/contrail' :
    ensure  => directory,
  } ->
  file { '/etc/contrail/issu.conf' :
    ensure  => file,
    content => template('tripleo/contrail/issu.conf.erb'),
  } ->
  file { '/tmp/issu_provision_control_nodes.sh' :
    ensure  => file,
    content => template('tripleo/contrail/issu_provision_control_nodes.sh.erb'),
  }

  #TODO:
}
