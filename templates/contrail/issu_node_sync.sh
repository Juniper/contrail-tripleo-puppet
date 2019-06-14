#!/bin/bash -x

my_file="$(readlink -e "$0")"
my_dir="$(dirname $my_file)"

issu_env_file=${issu_env_file-"$my_dir/issu.env"}

if [ -f "$issu_env_file" ] ; then
  source $issu_env_file
fi

if [[ -z "$ansible_deployer_image" && ( -z "$container_registry" || -z "$container_tag" ) ]] ; then
   echo "check that container_tag and container_registry are not empty if ansible_deployer_image is empty"
   exit -1
fi

host_home_dir=~
host_ssh_dir=${host_ssh_dir:-"$host_home_dir/.ssh"}
working_dir=${working_dir:-'/tmp/contrail_issu'}
config_api_image=${ansible_deployer_image:-"${container_registry}/contrail-controller-config-api:${container_tag}"}
issu_config=${issu_config:-'issu.conf'}
issu_config_file=$(echo "$issu_config" | awk -F '/' '{print($NF)}')

mkdir -p $working_dir

cp -f "$issu_config" "${working_dir}/"

cat << EOF > ${working_dir}/entrypoint.sh
#!/bin/bash -x
mkdir -p ~/.ssh
chmod 700 ~/.ssh
cp -f "$working_dir/ssh/issu_id_rsa" ~/.ssh/id_rsa
cp -f "$working_dir/ssh/issu_id_rsa.pub" ~/.ssh/id_rsa.pub
chown -R root:root ~/.ssh
/usr/bin/contrail-issu-pre-sync -c $working_dir/$issu_config_file
EOF
chmod +x ${working_dir}/entrypoint.sh

sudo docker run --rm -it --network host \
  -v "$working_dir":"$working_dir" \
  -v "$host_ssh_dir":"$working_dir/ssh":ro \
  --entrypoint ${working_dir}/entrypoint.sh \
  $config_api_image 

if [[ $? != 0 ]] ; then
  echo "ERROR: failed to run issu pre-sync"
  exit -1
fi

cat << EOF > ${working_dir}/entrypoint.sh
#!/bin/bash -x
mkdir -p ~/.ssh
chmod 700 ~/.ssh
cp -f "$working_dir/ssh/issu_id_rsa" ~/.ssh/id_rsa
cp -f "$working_dir/ssh/issu_id_rsa.pub" ~/.ssh/id_rsa.pub
chown -R root:root ~/.ssh
/usr/bin/contrail-issu-run-sync -c $working_dir/$issu_config_file
EOF
chmod +x ${working_dir}/entrypoint.sh

sudo docker run --rm --detach -it --network host --name issu-run-sync \
  -v "$working_dir":"$working_dir" \
  -v "$host_ssh_dir":"$working_dir/ssh":ro \
  --entrypoint ${working_dir}/entrypoint.sh \
  $config_api_image

echo "Waiting for sync initialization for 5 sec."
for i in {1..5} ; do
  sleep 1
  printf "."
done
echo ""
echo "Docker logs for issu-run-sync:"
sudo docker logs issu-run-sync
echo ""
echo "ISSU sync logs:"
sudo docker exec issu-run-sync cat /var/log/contrail/issu_contrail_run_sync.log
