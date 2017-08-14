# == Class dnsmasq::service
#
# This class is meant to be called from dnsmasq.
# It ensure the service is running.
#
class dnsmasq::service {
  assert_private()

  service { $::dnsmasq::service_name:
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true
  }
}
