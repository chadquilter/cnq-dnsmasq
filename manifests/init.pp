# Full description of SIMP module 'dnsmasq' here.
#
# === Welcome to SIMP!
#
# This module is a component of the System Integrity Management Platform, a
# managed security compliance framework built on Puppet.
#
# ---
# *FIXME:* verify that the following paragraph fits this module's characteristics!
# ---
#
# This module is optimally designed for use within a larger SIMP ecosystem, but
# it can be used independently:
#
# * When included within the SIMP ecosystem, security compliance settings will
#   be managed from the Puppet server.
#
# * If used independently, all SIMP-managed security subsystems are disabled by
#   default, and must be explicitly opted into by administrators.  Please
#   review the +trusted_nets+ and +$enable_*+ parameters for details.
#
# @param service_name
#   The name of the dnsmasq service
#
# @param package_name
#   The name of the dnsmasq package
#
# @param trusted_nets
#   A whitelist of subnets (in CIDR notation) permitted access
#
# @param enable_auditing
#   If true, manage auditing for dnsmasq
#
# @param enable_firewall
#   If true, manage firewall rules to acommodate dnsmasq
#
# @param enable_logging
#   If true, manage logging configuration for dnsmasq
#
# @param enable_pki
#   If true, manage PKI/PKE configuration for dnsmasq
#
# @param enable_selinux
#   If true, manage selinux to permit dnsmasq
#
# @param enable_tcpwrappers
#   If true, manage TCP wrappers configuration for dnsmasq
#
# @author Chad Quilter
#
class dnsmasq (
  String                        $service_name       = 'dnsmasq',
  String                        $package_name       = 'dnsmasq',
  Simplib::Port                 $tcp_listen_port    = 9999,
  Simplib::Netlist              $trusted_nets       = simplib::lookup('simp_options::trusted_nets', {'default_value' => ['127.0.0.1/32'] }),
  Boolean                       $enable_pki         = simplib::lookup('simp_options::pki', { 'default_value'         => false }),
  Boolean                       $enable_auditing    = simplib::lookup('simp_options::auditd', { 'default_value'      => false }),
  Variant[Boolean,Enum['simp']] $enable_firewall    = simplib::lookup('simp_options::firewall', { 'default_value'    => false }),
  Boolean                       $enable_logging     = simplib::lookup('simp_options::syslog', { 'default_value'      => false }),
  Boolean                       $enable_selinux     = simplib::lookup('simp_options::selinux', { 'default_value'     => false }),
  Boolean                       $enable_tcpwrappers = simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false }),
  String                        $auth_sec_servers         = undef,
  String                        $auth_server              = undef,
  String                        $auth_ttl                 = undef,
  String                        $auth_zone                = undef,
  Boolean                       $bogus_priv               = true,
  String                        $cache_size               = 1000,
  Hash                          $config_hash              = {},
  String                        $dhcp_boot                = undef,
  String                        $dhcp_leasefile           = undef,
  Boolean                       $dhcp_no_override         = false,
  String                        $domain                   = undef,
  Boolean                       $domain_needed            = true,
  String                        $dns_forward_max          = undef,
  String                        $dnsmasq_confdir          = '/var/log',
  String                        $dnsmasq_conffile         = '/etc/dnsmasq.d',
  String                        $dnsmasq_hasstatus        = 'true',
  String                        $dnsmasq_logdir           = '/var/log',
  String                        $dnsmasq_package          = 'dnsmasq',
  String                        $dnsmasq_package_provider = 'undef',
  String                        $dnsmasq_service          = 'dnsmasq',
  Boolean                       $enable_tftp              = false,
  Boolean                       $expand_hosts             = true,
  String                        $interface                = undef,
  String                        $listen_address           = undef,
  String                        $local_ttl                = undef,
  Boolean                       $manage_tftp_root         = false,
  String                        $max_ttl                  = undef,
  String                        $max_cache_ttl            = undef,
  String                        $neg_ttl                  = undef,
  String                        $no_dhcp_interface        = undef,
  Boolean                       $no_hosts                 = false,
  Boolean                       $no_negcache              = false,
  Boolean                       $no_resolv                = false,
  String                        $port                     = '53',
  Boolean                       $read_ethers              = false,
  Boolean                       $reload_resolvconf        = true,
  Boolean                       $resolv_file              = false,
  Boolean                       $restart                  = true,
  String                        $run_as_user              = undef,
  Boolean                       $save_config_file         = true,
  Boolean                       $service_enable           = true,
  String                        $service_ensure           = 'running',
  Boolean                       $strict_order             = true,
  String                        $tftp_root                = '/var/lib/tftpboot',
) {

  $oses = load_module_metadata( $module_name )['operatingsystem_support'].map |$i| { $i['operatingsystem'] }
  unless $::operatingsystem in $oses { fail("${::operatingsystem} not supported") }

  include '::dnsmasq::install'
  include '::dnsmasq::config'
  include '::dnsmasq::service'

  Class[ '::dnsmasq::install' ]
  -> Class[ '::dnsmasq::config' ]
  ~> Class[ '::dnsmasq::service' ]

  if $enable_pki {
    include '::dnsmasq::config::pki'
    Class[ '::dnsmasq::config::pki' ]
    -> Class[ '::dnsmasq::service' ]
  }

  if $enable_auditing {
    include '::dnsmasq::config::auditing'
    Class[ '::dnsmasq::config::auditing' ]
    -> Class[ '::dnsmasq::service' ]
  }

  if $enable_firewall {
    include '::dnsmasq::config::firewall'
    Class[ '::dnsmasq::config::firewall' ]
    -> Class[ '::dnsmasq::service' ]
  }

  if $enable_logging {
    include '::dnsmasq::config::logging'
    Class[ '::dnsmasq::config::logging' ]
    -> Class[ '::dnsmasq::service' ]
  }

  if $enable_selinux {
    include '::dnsmasq::config::selinux'
    Class[ '::dnsmasq::config::selinux' ]
    -> Class[ '::dnsmasq::service' ]
  }

  if $enable_tcpwrappers {
    include '::dnsmasq::config::tcpwrappers'
    Class[ '::dnsmasq::config::tcpwrappers' ]
    -> Class[ '::dnsmasq::service' ]
  }

  ## VALIDATION

    validate_bool(
      $bogus_priv,
      $dhcp_no_override,
      $domain_needed,
      $dnsmasq_hasstatus,
      $enable_tftp,
      $expand_hosts,
      $manage_tftp_root,
      $no_hosts,
      $no_negcache,
      $no_resolv,
      $save_config_file,
      $service_enable,
      $strict_order,
      $read_ethers,
      $reload_resolvconf,
      $restart
    )
    validate_hash($config_hash)
    validate_re($service_ensure,'^(running|stopped)$')
    if undef != $auth_ttl      { validate_re($auth_ttl,'^[0-9]+') }
    if undef != $local_ttl     { validate_re($local_ttl,'^[0-9]+') }
    if undef != $neg_ttl       { validate_re($neg_ttl,'^[0-9]+') }
    if undef != $max_ttl       { validate_re($max_ttl,'^[0-9]+') }
    if undef != $max_cache_ttl { validate_re($max_cache_ttl,'^[0-9]+') }
    if undef != $listen_address and !is_ip_address($listen_address) {
      fail("Expect IP address for listen_address, got ${listen_address}")
    }

    ## CLASS VARIABLES

    # Allow custom ::provider fact to override our provider, but only
    # if it is undef.
    $provider_real = empty($::provider) ? {
      true    => $dnsmasq_package_provider ? {
        undef   => $::provider,
        default => $dnsmasq_package_provider,
      },
      default => $dnsmasq_package_provider,
    }

    ## MANAGED RESOURCES

    concat { 'dnsmasq.conf':
      path    => $dnsmasq_conffile,
      warn    => true,
      require => Package['dnsmasq'],
    }

    concat::fragment { 'dnsmasq-header':
      order   => '00',
      target  => 'dnsmasq.conf',
      content => template('dnsmasq/dnsmasq.conf.erb'),
    }

    package { 'dnsmasq':
      ensure   => installed,
      name     => $dnsmasq_package,
      provider => $provider_real,
      before   => Service['dnsmasq'],
    }

    service { 'dnsmasq':
      ensure    => $service_ensure,
      name      => $dnsmasq_service,
      enable    => $service_enable,
      hasstatus => $dnsmasq_hasstatus,
    }

    if $restart {
      Concat['dnsmasq.conf'] ~> Service['dnsmasq']
    }

    if $dnsmasq_confdir {
      file { $dnsmasq_confdir:
        ensure => 'directory',
        owner  => 0,
        group  => 0,
        mode   => '0755',
      }
    }

    if $save_config_file {
      # let's save the commented default config file after installation.
      exec { 'save_config_file':
        command => "cp ${dnsmasq_conffile} ${dnsmasq_conffile}.orig",
        creates => "${dnsmasq_conffile}.orig",
        path    => [ '/usr/bin', '/usr/sbin', '/bin', '/sbin', ],
        require => Package['dnsmasq'],
        before  => Concat['dnsmasq.conf'],
      }
    }

    if $reload_resolvconf {
      exec { 'reload_resolvconf':
        provider => shell,
        command  => '/sbin/resolvconf -u',
        path     => [ '/usr/bin', '/usr/sbin', '/bin', '/sbin', ],
        user     => root,
        onlyif   => 'test -f /sbin/resolvconf',
        before   => Service['dnsmasq'],
        require  => Package['dnsmasq'],
      }
    }

    if $manage_tftp_root {
      file { $tftp_root:
        ensure => directory,
        owner  => 0,
        group  => 0,
        mode   => '0644',
        before => Service['dnsmasq'],
      }
    }

    if ! $no_hosts {
      Host <||> {
        notify +> Service['dnsmasq'],
      }
    }

    dnsmasq::address { "example-host-dns.int.lan":
      ip => '192.168.1.20',
    }

}
