# == Class dnsmasq::config
#
# This class is called from dnsmasq for service config.
#
class dnsmasq::config {
  File {
      owner => 'cquilter',
      group => 'cquilter',
    }

    file {
      $dnsmasq::params::config_file:
        mode   => '0644',
        source => 'puppet:///modules/dnsmasq/dnsmasq.conf';
    }
}
