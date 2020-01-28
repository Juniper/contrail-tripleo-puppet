
# Contrail ISSU
#

class tripleo::network::contrail::issu(
  $step                         = Integer(hiera('step')),
  $admin_tenant_name            = hiera('contrail::admin_tenant_name'),
  $admin_user                   = hiera('contrail::admin_user'),
  $admin_password               = hiera('contrail::admin_password'),
  $api_server                   = hiera('contrail_config_vip', hiera('internal_api_virtual_ip')),
  $api_port                     = hiera('contrail::api_port', 8082),
  $issu_api_port                = hiera('contrail::issu_api_port', 8082),
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
  $issu_control_ips             = hiera('contrail_issu_control_node_ips', hiera('contrail_issu_node_ips')),
  $issu_ssh_user                = hiera('contrail_issu_ssh_user'),
  $keystone_project_domain_name = hiera('contrail::keystone_project_domain_name','Default'),
  $keystone_region              = hiera('contrail::keystone_region','regionOne'),
  $keystone_user_domain_name    = hiera('contrail::keystone_user_domain_name','Default'),
  $rabbit_server                = hiera('contrail_database_node_ips'),
  $router_asn                   = hiera('contrail::control::asn', 64512),
  $zk_server_ip                 = hiera('contrail_database_node_ips'),
  $contrail_ssl_enabled         = hiera('contrail_ssl_enabled', false),
  $contrail_ssl_version         = hiera('contrail_ssl_version', 'sslv23'),
  $contrail_certificates_specs  = hiera('contrail_certificates_specs', undef),
  $contrail_ssl_ca_certs        = hiera('contrail_ssl_ca_certs', '/etc/contrail/ssl/certs/ca-cert.pem'),
  $contrail_ssl_certfile        = hiera('contrail::service_cert_file', '/etc/contrail/ssl/certs/server.pem'),
  $contrail_ssl_keyfile         = hiera('contrail::service_key_file', '/etc/contrail/ssl/private/server-privkey.pem'),
) {

  if $contrail_certificates_specs != undef {
    $contrail_ssl_ca_certs = '/etc/ipa/ca.crt'
  }

  File {
    mode  => '0644',
  }

  Exec {
    path => [ '/bin', '/usr/bin' ],
  }

  $old_cassandra_server_list_9161 = join([join($cassandra_server_list, ':9161 '),':9161'],'')

  $old_zk_server_ip_2181 = join([join($zk_server_ip, ':2181,'),':2181'],'')
  $old_rabbit_server_list_5673 = join([join($rabbit_server, ':5673,'),':5673'],'')
  $old_rabbit_server_list = join($rabbit_server, ',')
  # at revert step old should point to Contrail Config Database 
  # because 5.x Contrail has own rabbit
  $revert_issu_old_rabbit_server_list = join($zk_server_ip, ',')

  $issu_api_info = join(['{"', join([join($issu_ips, "\": [(\"${issu_ssh_user}\"), (\"\")],\"", ''), "\": [(\"${issu_ssh_user}\"), (\"\")]}"], '')], '')
  $revert_issu_api_info = join(['{"', join([join($old_config_servers, "\": [(\"${issu_ssh_user}\"), (\"\")],\"", ''), "\": [(\"${issu_ssh_user}\"), (\"\")]}"], '')], '')

  $first_old_config_server_ip = $old_config_servers[0]
  $old_config_servers_list_space = join($old_config_servers, ' ')
  $old_control_servers_list_space = join($old_control_servers, ' ')

  $old_analytics_servers_list_space = join($old_analytics_servers, ' ')
  $old_analyticsdb_servers_list_space = join($old_analyticsdb_servers, ' ')

  $issu_ips_list_space = join($issu_ips, ' ')
  $issu_ips_list_comma = join($issu_ips, ',')

  $issu_control_ips_space = join($issu_control_ips, ' ')

  $issu_cassandra_server_list_9161 = join([join($issu_ips, ':9161 '),':9161'],'')
  $issu_zk_server_ip_2181 = join([join($issu_ips, ':2181,'),':2181'],'')

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
    mode    => '0644',
  } ->
  file { "${issu_dir}/issu_revert.conf" :
    ensure  => file,
    content => template('tripleo/contrail/issu_revert.conf.erb'),
    mode    => '0644',
  } ->
  file { "${issu_dir}/issu.env" :
    ensure  => file,
    content => template("tripleo/contrail/issu.env.erb"),
  } ->
  file { "${issu_dir}/issu_node_pair.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_pair.sh'),
    mode    => '0755',
  } ->
  file { "${issu_dir}/issu_node_sync.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_sync.sh'),
    mode    => '0755',
  } ->
  file { "${issu_dir}/issu_node_sync_post.sh" :
    ensure  => file,
    content => template('tripleo/contrail/issu_node_sync_post.sh'),
    mode    => '0755',
  }
}
