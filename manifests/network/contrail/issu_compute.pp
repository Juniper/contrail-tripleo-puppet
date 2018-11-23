
# Contrail ISSU
#

class tripleo::network::contrail::issu_compute(
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
  $control_server               = hiera('contrail::vrouter::control_node_ips', hiera('contrail_control_node_ips')),
  $host_ip                      = hiera('contrail::issu::host_ip'),
  $host_ip_control              = hiera('contrail::issu::host_ip_control', hiera('contrail::issu::host_ip')),
  $ibgp_auto_mesh               = true,
  $issu_ips                     = hiera('contrail_issu_node_ips', undef),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $metadata_secret              = hiera('contrail::vrouter::metadata_proxy_shared_secret'),
  $metadata_host_ip             = hiera('internal_api_virtual_ip'),
  $router_asn                   = hiera('contrail::control::asn'),
  $ssl_enabled                  = hiera('contrail_ssl_enabled', false),
  $vrouter_ips                  = hiera('contrail_vrouter_node_ips', []),
  $dpdk_ips                     = hiera('contrail_dpdk_node_ips', []),  
  $tsn_ips                      = hiera('contrail_tsn_node_ips', []),  
) {
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

  $control_server_list_space = join($control_server, ' ')
  if $issu_ips {
    $issu_ips_list_space = join($issu_ips, ' ')
    $issu_ips_list_comma = join($issu_ips, ',')
  } else {
    $issu_ips_list_space = $host_ip
    $issu_ips_list_comma = $host_ip
  }
  
  $issu_control_servers_list_comma = $host_ip_control
  $compute_nodes = concat($vrouter_ips, $dpdk_ips, $tsn_ips)

  file { '/etc/contrail' :
    ensure  => directory,
  } ->
  file { '/etc/contrail/instances.yaml' :
    ensure  => file,
    content => template('tripleo/contrail/instances_common.yaml.erb', 'tripleo/contrail/instances_computes.yaml.erb'),
  }

  #TODO:
}