# == Class dnsmasq::config::selinux
#
# This class is meant to be called from dnsmasq.
# It ensures that selinux rules are defined.
#
class dnsmasq::config::selinux {
  assert_private()

  # FIXME: ensure your module's selinux settings are defined here.
  $msg = "FIXME: define the ${module_name} module's selinux settings."

  notify{ 'FIXME: selinux': message => $msg } # FIXME: remove this and add logic
  err( $msg )                                 # FIXME: remove this and add logic

}
