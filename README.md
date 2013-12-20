lair-drone-msf
==============

Lair drone for the Metasploit Framework

##Status##
Currently, this drone only imports/exports hosts, ports, and credentials. This drone is mostly untested and still in active development.

##Install##
As we're in current development, we are not yet providing compiled releases. As a result, you must use Go to download, compile, and install yourself. If you are desperate you can email me and I will compile it for you. After setting up your go workspace:
```
$ go install github.com/tomsteele/lair-drone-msf
$ which lair-drone-msf
```

##Usage##
```
$ drone-msf -h
Usage:
  drone-msf import [--scope <file>] <lpid> <file>
  drone-msf export <lpid> <file>
  drone-msf -h | --help
  drone-msf --version

Options:
  -h, --help      Show usage.
  --version       Show version.
  --scope <file>  Only import hosts that are in a file containing a line
                  separated list of hosts and/or networks (CIDR).
```
