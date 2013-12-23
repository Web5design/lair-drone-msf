package main

const usage = `

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
`
