# == Class dnsmasq::install
#
# This class is called from dnsmasq for install.
#
class dnsmasq::install {
  assert_private()

  package { $::dnsmasq::package_name:
    ensure => present
  }
}
