# wazuh-freebsd
Resources for a better integration between  FreeBSD and Wazuh SIEM

## FreeBSD Security Configuration Assessment for Wazuh (var/ossec/ruleset/sca)

## FreeBSD decoders and rules for Wazuh (var/ossec/ruleset/decoders,  var/ossec/ruleset/rules)

## Install 
```sh
pkg install openjdk17

# add /etc/fstab
fdesc	/dev/fd		fdescfs		rw	0	0
proc	/proc		procfs		rw	0	0
# -------------------------------------------

pkg install bash wazuh-indexer wazuh-server wazuh-dashboard
```
