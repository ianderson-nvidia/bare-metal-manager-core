# Kernel modules kept out of every boot image.
#
# From mkosi.extra/etc/modprobe.d/disable-mods.conf. These are network protocol
# and crypto modules with a history of CVEs that none of these images has any
# use for.
#
# `install <mod> /bin/false` rather than `blacklist <mod>`: blacklisting only
# suppresses autoloading by alias, so an explicit modprobe — or a subsystem
# that requests the module by name rather than by alias — still loads it.
{ ... }:

{
  boot.extraModprobeConfig = ''
    install algif_aead /bin/false
    install esp4 /bin/false
    install esp6 /bin/false
    install rxrpc /bin/false
    install rds /bin/false
    install rds_tcp /bin/false
  '';
}
