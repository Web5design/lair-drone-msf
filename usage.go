package main

var usage = `

Usage:
  drone-msf import [options] <lpid> <file>
  drone-msf export [options] <lpid> <file>
  drone-msf -h | --help
  drone-msf --version

Options:
  -h, --help      Show usage.
  --version       Show version.
  --scope <file>  Only import or export hosts that are in a
                  given a file containing a line separated
                  list of hosts and/or networks (CIDR).
  --no-hosts      Do not create new hosts when importing.
  --no-vulns      Do not create new vulnerabilities when importing.
  --no-creds      Do not create new credentials when importing.
  --dry-run       Dump JSON to stdout and do not insert/update Lair.

`
