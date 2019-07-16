
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
  $container_registry           = hiera('contrail_issu_container_registry'),
  $container_tag                = hiera('contrail_issu_container_tag'),
  $old_control_servers          = hiera('contrail::vrouter::control_node_ips', hiera('contrail_control_node_ips')),
  $host_ip                      = hiera('contrail_issu_host_ip'),
  $ibgp_auto_mesh               = true,
  $issu_ips                     = hiera('contrail_issu_node_ips'),
  $issu_control_ips             = hiera('contrail_issu_control_node_ips', hiera('contrail_issu_node_ips')),
  $is_dpdk                      = hiera('contrail::vrouter::is_dpdk',false),
  $is_tsn                       = hiera('contrail::vrouter::is_tsn',false),
  $sriov_on                     = hiera('contrail::vrouter::sriov_on', false),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $metadata_secret              = hiera('contrail::vrouter::metadata_proxy_shared_secret'),
  $metadata_host_ip             = hiera('internal_api_virtual_ip'),
  $router_asn                   = hiera('contrail::control::asn'),
  $vrouter_gateway              = hiera('contrail::vrouter::gateway'),
  $vhost_user_mode              = hiera('contrail::vrouter::vhost_user_mode', ''),
  $ssl_enabled                  = hiera('contrail_ssl_enabled', false),
  $internal_api_ssl             = hiera('contrail_internal_api_ssl', false),
  $ca_file                      = hiera('contrail::ca_cert_file', undef),
  $ca_cert                      = hiera('contrail::ca_cert', undef),
  $ca_key_file                  = hiera('contrail::ca_key_file', undef),
  $ca_key                       = hiera('contrail::ca_key', undef),
  $key_file                     = hiera('contrail::service_key_file', undef),
  $cert_file                    = hiera('contrail::service_cert_file', undef),
) {

  File {
    mode  => 644,
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

  $old_control_servers_list_space = join($old_control_servers, ' ')
  
  $issu_ips_list_space = join($issu_ips, ' ')
  $issu_ips_list_comma = join($issu_ips, ',')

  $issu_control_ips_list_space = join($issu_control_ips, ' ')
  $issu_control_ips_list_comma = join($issu_control_ips, ',')

  $tripleo_cfg_dir = '/var/lib/tripleo-config'
  $instances_yaml_file_name="instances-${::hostname}.yaml"
  $issu_dir='/etc/contrail/issu'
  exec { 'set selinux to permissive issu' :
    command => 'setenforce permissive',
    path    => '/bin:/sbin:/usr/bin:/usr/sbin',
    onlyif  => 'sestatus | grep -i "Current mode" | grep -q enforcing',
  } ->
  file { '/etc/contrail' :
    ensure  => directory,
  } ->
  file { $issu_dir :
    ensure  => directory,
  } ->
  file { "${issu_dir}/issu_compute_deploy.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_compute_deploy.sh.erb'),
    mode    => 755,
  } ->
  file { $tripleo_cfg_dir :
    ensure  => directory,
  } ->
  file { '/var/log/containers' :
    ensure  => directory,
  } ->
  file { "${tripleo_cfg_dir}/hashed-docker-container-startup-config-step_1.json" :
    ensure  => file,
    content => template("tripleo/contrail/docker_step1_config.json.erb"),
    mode    => 600,
  } ->
  file { "${tripleo_cfg_dir}/hashed-docker-container-startup-config-step_2.json" :
    ensure  => file,
    content => template("tripleo/contrail/docker_step2_config.json.erb"),
    mode    => 600,
  } ->
  file { "${tripleo_cfg_dir}/hashed-docker-container-startup-config-step_3.json" :
    ensure  => file,
    content => template("tripleo/contrail/docker_step3_config.json.erb"),
    mode    => 600,
  } ->
  file { "${tripleo_cfg_dir}/hashed-docker-container-startup-config-step_5.json" :
    ensure  => file,
    content => template("tripleo/contrail/docker_step5_config.json.erb"),
    mode    => 600,
  } ->
  file { "/etc/contrail/common_contrail.env" :
    ensure  => file,
    content => template("tripleo/contrail/common_contrail.env.erb"),
  } ->
  file { "/etc/contrail/common_vrouter.env" :
    ensure  => file,
    content => template("tripleo/contrail/common_vrouter.env.erb"),
  }
}
