#
# Copyright (C) 2015 Juniper Networks
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
# == Class: tripleo::network::contrail::config
#
# Configure Contrail Config services
#
# == Parameters:
#
# [*ssl_enabled*]
#  (optional) SSL should be used in internal Contrail services communications
#  Boolean value.
#  Defaults to hiera('contrail_ssl_enabled', false)
#
# [*ca_file*]
#  (optional) ca file name
#  String value.
#  Defaults to hiera('contrail::ca_cert_file',false)
#
# [*key_file*]
#  (optional) key file name
#  String value.
#  Defaults to hiera('contrail::service_key_file',false)
#
# [*cert_file*]
#  (optional) cert file name
#  String value.
#  Defaults to hiera('contrail::service_cert_file',false)
#
# [*certmonger_ca*]
#   (Optional) The CA that certmonger will use to generate the certificates.
#   Defaults to hiera('certmonger_ca', 'local').
#

class tripleo::network::contrail::certmonger(
  $host_ip,
  $ssl_enabled,
  $key_file,
  $cert_file,
  $ca_file        = undef,
  $ca_cert        = undef,
  $ca_key_file    = undef,
  $ca_key         = undef,
  $auth_ca_file   = undef,
  $auth_ca_cert   = undef,
  $owner          = undef,
  $group          = undef,
  $certmonger_ca  = hiera('certmonger_ca', 'local'),
  $principal      = undef,
  $postsave_cmd   = undef,
) {
  if $ssl_enabled {

    File {
      owner => $owner,
      group => $group,
    }
    Exec {
      path => [ '/bin', '/usr/bin' ],
    }

    # prepare dirs
    $key_file_dir = dirname($key_file)
    exec { 'key_file_dir':
      command => "mkdir -p ${key_file_dir}",
    }
    $cert_file_dir = dirname($cert_file)
    exec { 'cert_file_dir':
      command => "mkdir -p ${cert_file_dir}",
    }
    $ca_file_dir = dirname($ca_file)
    exec { 'ca_file_dir':
      command => "mkdir -p ${ca_file_dir}",
    }
    if $ca_key_file {
      $cakey_file_dir = dirname($ca_key_file)
      exec { 'cakey_file_dir':
        command => "mkdir -p ${cakey_file_dir}",
      }
    }
    if $auth_ca_file and $auth_ca_cert {
      $auth_ca_file_dir = dirname($auth_ca_file)
      exec { 'auth_ca_file_dir':
        command => "mkdir -p ${auth_ca_file_dir}",
      } ->
      file { $auth_ca_file :
        content => $auth_ca_cert,
        mode    => '0644',
        require => Exec['ca_file_dir'],
      }
    }

    # Generate certificates
    if $ca_cert and $ca_key_file and $ca_key {
      # use provided CA for cert generation
      $working_dir = '/tmp/contrail_ssl_gen'
      $csr_file = "${working_dir}/server.pem.csr"
      $openssl_config_file = "${working_dir}/contrail_openssl.cfg"
      $openssl_config = "[req]
default_bits = 2048
prompt = no
default_md = sha256
default_days = 375
req_extensions = v3_req
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[ req_distinguished_name ]
countryName = US
stateOrProvinceName = California
localityName = Sannyvale
0.organizationName = OpenContrail
commonName = $::hostname

[ v3_req ]
basicConstraints = CA:false
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $::fqdn
DNS.2 = $::hostname
IP.1 = $host_ip

[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $working_dir
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/certs
database          = \$dir/index.txt
serial            = \$dir/serial.txt
RANDFILE          = \$dir/.rand
# For certificate revocation lists.
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
# The root key and root certificate.
private_key       = $ca_key_file
certificate       = $ca_file
# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_optional

[ policy_optional ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ v3_ca]
# Extensions for a typical CA
# PKIX recommendation.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true

[ crl_ext ]
authorityKeyIdentifier=keyid:always,issuer:always
"
      file { $cert_file_dir :
        ensure  => 'directory',
        selrole => 'object_r',
        seltype => 'cert_t',
        seluser => 'system_u',
        require => Exec['cert_file_dir'],
      } ->
      file { $key_file_dir :
        ensure  => 'directory',
        selrole => 'object_r',
        seltype => 'cert_t',
        seluser => 'system_u',
        require => Exec['key_file_dir'],
      } ->
      exec { 'prepare_working_dir':
        command => "rm -rf ${working_dir} && mkdir -p ${working_dir}/certs",
      } ->
      exec { 'prepare_working_files':
        command => "touch ${working_dir}/index.txt ${working_dir}/index.txt.attr && cat <<<01 >${working_dir}/serial.txt",
      } ->
      file { $openssl_config_file :
        content => $openssl_config,
      } ->
      file { $ca_file :
        content => $ca_cert,
        mode    => '0644',
        require => Exec['ca_file_dir'],
      } ->
      file { $ca_key_file :
        content => $ca_key,
        mode    => '0600',
        require => Exec['cakey_file_dir'],
      } ->
      exec { 'gen_private_key':
        command => "openssl genrsa -out ${key_file} 2048",
      } ->
      exec { 'mk_csr':
        command => "openssl req -config ${openssl_config_file} -key ${key_file} -new  -out ${csr_file}",
      } ->
      exec { 'mk_cert':
        command => "yes | openssl ca -config ${openssl_config_file} -extensions v3_req -in ${csr_file} -out ${cert_file}",
      } ->
      file { $cert_file :
        mode    => '0644',
      } ->
      file { $key_file :
        mode    => '0600',
      }
    } else {
      # NOTE: branch is not tested with other then certmonger_ca=local

      # Generate certificates via certmonger
      # For that case to work IPA should be used
      # because certmonger local CA is unable to be verified
      # on other hosts, but contral requires to use CA file.
      # So, CA file should be provided by deployer in another way
      include ::certmonger
      if $certmonger_ca == 'local' {
        include ::tripleo::certmonger::ca::local
        $local_ca_pem = getparam(Class['tripleo::certmonger::ca::local'], 'ca_pem')
        file { $ca_file :
          source  => $local_ca_pem,
          mode    => '0644',
          require => [ Class['tripleo::certmonger::ca::local'], Exec['ca_file_dir']],
        }
      } else {
        # To check that ca file exists
        exec { 'check_ca_file':
          command => "test -f ${ca_file}",
          before  => Certmonger_certificate['contrail'],
        }
      }
      file { $cert_file_dir :
        ensure  => 'directory',
        selrole => 'object_r',
        seltype => 'cert_t',
        seluser => 'system_u',
        require => Exec['cert_file_dir'],
        before  => Certmonger_certificate['contrail'],
      }
      file { $key_file_dir :
        ensure  => 'directory',
        selrole => 'object_r',
        seltype => 'cert_t',
        seluser => 'system_u',
        require => Exec['key_file_dir'],
        before  => Certmonger_certificate['contrail'],
      }
      certmonger_certificate { 'contrail' :
        ensure       => 'present',
        certfile     => $cert_file,
        keyfile      => $key_file,
        hostname     => $host_ip,
        dnsname      => $::hostname,
        principal    => $principal,
        postsave_cmd => $postsave_cmd,
        ca           => $certmonger_ca,
        wait         => true,
        require      => Class['::certmonger'],
      }
      file { $cert_file :
        mode    => '0644',
        require => Certmonger_certificate['contrail'],
      }
      file { $key_file :
        mode    => '0600',
        require => Certmonger_certificate['contrail'],
      }
    }
  }
}
