# == Class dnsmasq::config::firewall
#
# This class is meant to be called from dnsmasq.
# It ensures that firewall rules are defined.
#
class dnsmasq::config::firewall {
  assert_private()

  # FIXME: ensure your module's firewall settings are defined here.
  iptables::listen::tcp_stateful { 'allow_dnsmasq_tcp_connections':
    trusted_nets => $::dnsmasq::trusted_nets,
    dports       => $::dnsmasq::tcp_listen_port
  }
}
