# Copyright (C) 2018 Juniper Networks
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
# == class: tripleo::network::contrail::certmonger_user
#
# Profile that ensures that the relevant certmonger certificates have been
# requested. The certificates come from the hiera set by the specific profiles
# and come in a pre-defined format.
#   contrail_certificates_specs:
#     hostname: <overcloud controller fqdn>
#     service_certificate: <service certificate path>
#     service_key: <service key path>
#     principal: "contrail/<contrail node fqdn>"
#

class tripleo::network::contrail::certmonger_user (
  $contrail_certificates_specs  = hiera('contrail_certificates_specs', {}),
) {
  unless empty($contrail_certificates_specs) {
    include ::tripleo::certmonger::contrail_dirs
    ensure_resource('class', 'tripleo::certmonger::contrail', $contrail_certificates_specs)
  }
}
