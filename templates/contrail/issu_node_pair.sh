#!/bin/bash

my_file="$(readlink -e "$0")"
my_dir="$(dirname $my_file)"

issu_env_file=${issu_env_file-"$my_dir/issu.env"}

if [ -f "$issu_env_file" ] ; then
  source "$issu_env_file"
fi

if [[ -z "$admin_user" || \
      -z "$admin_tenant_name" || \
      -z "$admin_password" || \
      -z "$router_asn" || \
      -z "$issu_ips_list_space" || \
      -z "$issu_control_ips_space" || \
      -z "$issu_api_server_ip" || \
      -z "$old_api_server_ip" || \
      -z "$old_control_servers_list_space" ]] ; then
   echo "check that admin_user, admin_tenant_name, admin_password, router_asn, issu_ips_list_space, issu_control_ips_space, issu_api_server_ip, old_api_server_ip, old_control_servers_list_space are not empty."
   exit -1
fi

control_container_id=${control_container_id:-`sudo docker ps | awk '/control_nodemgr/{print $1}' | head -n 1`}
config_container_id=${control_container_id:-`sudo docker ps | awk '/config_nodemgr/{print $1}' | head -n 1`}
analytics_container_id=${analytics_container_id:-`sudo docker ps | awk '/analytics_nodemgr/{print $1}' | head -n 1`}
analyticsdb_container_id=${analyticsdb_container_id:-`sudo docker ps | awk '/analytics_database_nodemgr/{print $1}' | head -n 1`}
issu_api_port=${issu_api_port:-8082}
old_api_server_port=${old_api_server_port:-8082}
working_dir=${working_dir:-'/tmp/contrail_issu'}
old_analytics_servers_list_space=${old_analytics_servers_list_space:-"$old_control_servers_list_space"}
old_analyticsdb_servers_list_space=${old_analyticsdb_servers_list_space:-"$old_analytics_servers_list_space"}

oper=${1:-'add'}
step=${2:-'pair_with_old'}

AUTH_PARAMS="--admin_password $admin_password"
AUTH_PARAMS+=" --admin_tenant_name $admin_tenant_name"
AUTH_PARAMS+=" --admin_user $admin_user"

asn_opts="--router_asn $router_asn"

bgp_auto_mesh_opts=''
if [[ ${ibgp_auto_mesh,,} == 'true' ]] ; then
  bgp_auto_mesh_opts="--ibgp_auto_mesh"
fi

mkdir -p "$working_dir"

ssh_opts='-i ~/.ssh/issu_id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

function resolve_name() {
  local ip=$1
  local ssh_cmd="ssh $ssh_opts heat-admin@${ip}"
  local release=$($ssh_cmd sudo docker inspect contrail-node-init | jq '.[].Config.Labels.release')
  if [[ "$release" =~ '5.0' ]] ; then
    # for 5.0 use short name
    $ssh_cmd uname -n
  else
    resolveip -s $ip
  fi
}

function provision() {
  local ip=$1
  shift 1
  local name=$1
  shift 1
  local api=$1
  shift 1
  local port=$1
  shift 1
  local provision_script=$1
  shift 1
  local container_id=$1
  shift 1
  local opts="$@"

  cat << EOF > ${working_dir}/provision_issu.sh
#!/bin/bash
LOG_LEVEL=SYS_NOTICE
source /common.sh
set_third_party_auth_config
set_vnc_api_lib_ini
python /opt/contrail/utils/${provision_script} --host_name $name \
  --host_ip $ip \
  --api_server_ip $api \
  --api_server_port $port \
  --oper $oper \
  $AUTH_PARAMS $opts
EOF
  chmod +x ${working_dir}/provision_issu.sh
  # /var/crashes/ is mounted to nodemgr containers, so use
  # it instead of copying file via docker cp because
  # it fails often by a nature do docker cp
  sudo cp -f ${working_dir}/provision_issu.sh /var/crashes/
  local output=$(sudo docker exec -it $container_id /var/crashes/provision_issu.sh 2>&1)
  if ! echo "$output" | grep -q 'not found' ; then
    echo "$output"
  fi
  sudo rm -f /var/crashes/provision_issu.sh  
}

function provision_control() {
  local ip=$1
  local name=$2
  local api=$3
  local port=$4

  provision $ip $name $api $port provision_control.py $control_container_id $asn_opts $bgp_auto_mesh_opts
}

docker_containers_filter='config_device_manager\|config_schema\|config_svc_monitor'
if [[ "$oper" == 'add' && "$step" == 'pair_with_old' ]] ; then
  #Stop containers:  contrail-device-manager, contrail-schema-transformer, contrail-svcmonitor:
  for ip in $issu_ips_list_space ; do
    cat << EOF | ssh $ssh_opts heat-admin@${ip}
for i in \$(sudo docker ps | grep "$docker_containers_filter" | awk '{print(\$1)}') ; do
  sudo docker stop \$i
done
EOF
  done
fi

if [[ "$oper" == 'del' && "$step" == 'pair_with_old' ]] ; then
  #Start containers on ISSU:  contrail-device-manager, contrail-schema-transformer, contrail-svcmonitor:
  for ip in $issu_ips_list_space ; do
    cat << EOF | ssh $ssh_opts heat-admin@${ip}
for i in \$(sudo docker ps --all | grep "$docker_containers_filter" | awk '{print(\$1)}') ; do
  sudo docker start \$i
done
EOF
  done
fi

if [[ "$oper" == 'add' && "$step" == 'pair_with_new' ]] ; then
  #Stop containers on newly deployd cluster:  contrail-device-manager, contrail-schema-transformer, contrail-svcmonitor:
  for ip in $old_control_servers_list_space ; do
    cat << EOF | ssh $ssh_opts heat-admin@${ip}
for i in \$(sudo docker ps |grep "$docker_containers_filter" | awk '{print(\$1)}') ; do
  sudo docker stop \$i
done
EOF
  done
fi

#Pair/unpair control nodes with issu node.
for ip in $old_control_servers_list_space ; do
  name=$(resolve_name $ip)
  provision_control $ip $name $issu_api_server_ip $issu_api_port || {
    echo "ERROR: failed to provision old control node $ip in ISSU cluster"
    exit -1
  }
done

#Pair/unpair issu control nodes in with cluster
for ip in $issu_control_ips_space ; do
  name=$(resolve_name $ip)
  provision_control $ip $name $old_api_server_ip $old_api_server_port|| {
    echo "ERROR: failed to provision ISSU control node $ip in old cluster $old_api_server_ip:$old_api_server_port"
    exit -1
  }
done

if [[ "$oper" == 'del' && "$step" == 'pair_with_old' ]] ; then
  # remove from iss node old config, analytics & analytics db nodes registered by issu_sync
  for ip in $old_control_servers_list_space ; do
    name=$(resolve_name $ip)
    provision $ip $name $issu_api_server_ip $issu_api_port provision_config_node.py $config_container_id
  done
  for ip in $old_analytics_servers_list_space ; do
    name=$(resolve_name $ip)
    provision $ip $name $issu_api_server_ip $issu_api_port provision_analytics_node.py $analytics_container_id
  done
  for ip in $old_analyticsdb_servers_list_space ; do
    name=$(resolve_name $ip)
    provision $ip $name $issu_api_server_ip $issu_api_port provision_database_node.py $analyticsdb_container_id
  done
fi

if [[ "$oper" == 'del' && "$step" == 'pair_with_new' ]] ; then
  #Start containers on newly deployd cluster:  contrail-device-manager, contrail-schema-transformer, contrail-svcmonitor:
  for ip in $old_control_servers_list_space ; do
    cat << EOF | ssh $ssh_opts heat-admin@${ip}
for i in \$(sudo docker ps --all | grep "$docker_containers_filter" | awk '{print(\$1)}') ; do
  sudo docker start \$i
done
EOF
  done

  sleep 10

  # remove ISSU node components from the cluster (they were synced by revers issu sync)
  for ip in $issu_ips_list_space ; do
    name=$(resolve_name $ip)
    # config
    provision $ip $name $old_api_server_ip $old_api_server_port provision_config_node.py $config_container_id
    # analytics
    provision $ip $name $old_api_server_ip $old_api_server_port provision_analytics_node.py $analytics_container_id
    # analytics db
    provision $ip $name $old_api_server_ip $old_api_server_port provision_database_node.py $analyticsdb_container_id
  done
fi
