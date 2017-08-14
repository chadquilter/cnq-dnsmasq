define dnsmasq::conf (
  $ensure  = 'present',
  $prio    = 10,
  $source  = undef,
  $content = undef,
  $config_dir = '/etc/dnsmasq.d/'
) {
  include ::dnsmasq

  file { "/etc/dnsmasq.d/10-test":
    ensure  => $ensure,
    owner   => 'root',
    group   => 'root',
    content => $content,
    source  => $source,
    notify  => Class['dnsmasq::service'],
  }
}
