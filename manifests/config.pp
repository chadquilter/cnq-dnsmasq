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
      '/etc/dnsmasq.conf':
        mode   => '0644',
        source => 'puppet:///modules/dnsmasq/dnsmasq.conf';
    }
}
