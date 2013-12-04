package main

import (
	"fmt"
	"labix.org/v2/mgo"
)

// Gathers hosts, ports (with creds), and vulnerabilities from Lair and exports
// to file containing  MSF compatible XML.
func msfExport(s *mgo.Session, lpid, fileName string) error {
	fmt.Println(s, lpid, fileName)
	return nil
}
