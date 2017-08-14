# == Class dnsmasq::install
#
# This class is called from dnsmasq for install.
#
class dnsmasq::install inherits dnsmasq {

  if $dnsmasq::package_manage {
    package { $dnsmasq::package_name:
      ensure => $dnsmasq::package_ensure,
    }
  }
}
