#!/bin/bash

my_file="$(readlink -e "$0")"
my_dir="$(dirname $my_file)"

issu_env_file=${issu_env_file-"$my_dir/issu.env"}

if [ -f "$issu_env_file" ] ; then
  source $issu_env_file
fi

if [[ -z "$config_api_image" && ( -z "$container_registry" || -z "$container_tag" ) ]] ; then
   echo "check that container_tag and container_registry are not empty if config_api_image is empty"
   exit -1
fi

host_home_dir=~
host_ssh_dir=${host_ssh_dir:-"$host_home_dir/.ssh"}
working_dir=${working_dir:-'/tmp/contrail_issu'}
config_api_image=${config_api_image:-}
if [[ -z "$config_api_image" ]] ; then
  config_api_image=$(docker images  | awk '/contrail-controller-config-api/{print($1":"$2)}')
  [ -z "$config_api_image" ] && config_api_image="${container_registry}/contrail-controller-config-api:${container_tag}"
fi
issu_config=${issu_config:-'issu.conf'}
issu_config_file=$(echo "$issu_config" | awk -F '/' '{print($NF)}')


echo "Stop and remove issu sync container"
sudo docker rm --force issu-run-sync || true

echo "Post sync operations"
mkdir -p $working_dir
cp -f "$issu_config" "${working_dir}/"

cat << EOF > ${working_dir}/entrypoint.sh
#!/bin/bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
cp -f "$working_dir/ssh/issu_id_rsa" ~/.ssh/id_rsa
cp -f "$working_dir/ssh/issu_id_rsa.pub" ~/.ssh/id_rsa.pub
chown -R root:root ~/.ssh
/usr/bin/contrail-issu-post-sync -c $working_dir/$issu_config_file
/usr/bin/contrail-issu-zk-sync -c $working_dir/$issu_config_file
EOF
chmod +x ${working_dir}/entrypoint.sh

sudo docker run --rm -t --network host \
  -v "$working_dir":"$working_dir" \
  -v "$host_ssh_dir":"$working_dir/ssh":ro \
  --entrypoint ${working_dir}/entrypoint.sh \
  $config_api_image 
