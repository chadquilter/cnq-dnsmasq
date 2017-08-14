# == Class dnsmasq::config
#
# This class is called from dnsmasq for service config.
#
class dnsmasq::config {
  File {
    owner => 'root',
    group => 'root',
  }

  file {
    dnsmasq::params::config_file:
      mode   => '0644',
      source => 'puppet:///modules/dnsmasq/dnsmasq.conf';

#    $dnsmasq::params::config_dir:
#      ensure  => 'directory',
#      recurse => true,
#      purge   => true,
#      force   => true;
  }
}
