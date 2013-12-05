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
`
