define dnsmasq::conf (
  $ensure  = 'present',
  $prio    = 10,
  $source  = undef,
  $content = undef
) {
  include ::dnsmasq

  file { "${dnsmasq::params::config_dir}${prio}-${name}":
    ensure  => $ensure,
    owner   => 'cquilter',
    group   => 'cquilter',
    content => $content,
    source  => $source,
    notify  => Class['dnsmasq::service']
}
