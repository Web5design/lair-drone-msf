package main

import (
	"github.com/tomsteele/golair"
	"io"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"os"
	"log"
	"strconv"
	"strings"
)

// Gathers hosts, ports (with creds), and vulnerabilities from Lair and exports
// to file containing  MSF compatible XML.
func msfExport(s *mgo.Session, lpid, fileName string) error {
	hosts := []golair.Host{}

	xmlOut := []string{}
	xmlOut = append(xmlOut, `<?xml version="1.0" encoding="UTF-8"?>`)
	xmlOut = append(xmlOut, `<MetasploitV4>`)
	xmlOut = append(xmlOut, `<generated time="" user="root" project="default" product="framework"/>`)

	// assign query to array of host structs from golair here
	// s is a session to a mongodb instance
	// DB("") returns a Database type, it is empty which uses the database that was in the URL provided to the Session object
	// C("hosts") returns a value representing the "hosts" collection
	// find prepares a query using the provided document in the form of a map or struct value capable of being marshalled with bson
	s.DB("").C("hosts").Find(bson.M{"project_id": lpid}).All(&hosts)

	xmlOut = append(xmlOut, `<hosts>`)

	// loop on each host that was returned
	for _, host := range hosts {
		// retrieve all ports for each host which should also contain credential information
		//fmt.Println(host.StringAddr)

		// New host, kick off xml starter
		xmlOut = append(xmlOut, `<host>`)
		xmlOut = append(xmlOut, `<id></id>`)
		xmlOut = append(xmlOut, `<created-at></created-at>`)
		xmlOut = append(xmlOut, `<address>`+host.StringAddr+`</address>`)
		xmlOut = append(xmlOut, `<mac/><comm></comm>`)
		xmlOut = append(xmlOut, `<name></name>`)
		xmlOut = append(xmlOut, `<state>alive</state>`)
		xmlOut = append(xmlOut, `<os-name></os-name>`+
			`<os-flavor></os-flavor>`+
			`<os-sp/>`+
			`<os-lang/>`+
			`<arch/>`+
			`<workspace-id></workspace-id>`+
			`<updated-at></updated-at>`+
			`<purpose>device</purpose>`+
			`<info/>`+
			`<comments/>`+
			`<scope/>`+
			`<virtual-host/>`+
			`<note-count></note-count>`+
			`<vuln-count></vuln-count>`+
			`<service-count></service-count>`+
			`<host-detail-count></host-detail-count>`+
			`<exploit-attempt-count></exploit-attempt-count>`+
			`<cred-count></cred-count>`+
			`<nexpose-data-asset-id/>`+
			`<history-count></history-count>`+
			`<host_details>`+
			`</host_details>`+
			`<exploit_attempts>`+
			`</exploit_attempts>`)

		// Services section
		xmlOut = append(xmlOut, `<services>`)
		ports := []golair.Port{}
		s.DB("").C("ports").Find(bson.M{"host_id": host.ID}).All(&ports)

		for _, port := range ports {
			xmlOut = append(xmlOut, `<service>`+
				`<id></id>`+
				`<host-id></host-id>`+
				`<created-at></created-at>`+
				`<port>`+strconv.Itoa(port.Port)+`</port>`+
				`<proto>`+port.Protocol+`</proto>`+
				`<state>open</state>`+
				`<name>`+port.Service+`</name>`+
				`<updated-at></updated-at>`+
				`<info></info>`+
				`</service>`)
		}

		// Notes section
		xmlOut = append(xmlOut, `</services><notes>`+
			`<note>`+
			`<id></id>`+
			`<created-at></created-at>`+
			`<ntype></ntype>`+
			`<workspace-id></workspace-id>`+
			`<service-id/>`+
			`<host-id></host-id>`+
			`<updated-at></updated-at>`+
			`<critical/>`+
			`<seen/>`+
			`<data></data>`+
			`</note>`+
			`</notes>`+
			`<vulns>`+
			`</vulns>`+
			`<creds>`)

		// Creds section
		// Have to loop by port because lair stores creds based on port, can probably do this easier
		// also need to add logic to add the password OR hash value, not just the password
		for _, port := range ports {
			for _, cred := range port.Credentials {
				xmlOut = append(xmlOut, `<cred>`+
					`<port>`+strconv.Itoa(port.Port)+`</port>`+
					`<sname/>`+
					`<created-at></created-at>`+
					`<updated-at></updated-at>`+
					`<user>`+cred.Username+`</user>`+
					`<pass>`+cred.Password+`</pass>`+
					`<active>true</active>`+
					`<proof/>`+
					`<ptype>password</ptype>`+
					`<source-type/>`+
					`</cred>`)
			}
		}

		xmlOut = append(xmlOut, `</creds></host>`)
	}

	xmlOut = append(xmlOut, `</hosts></MetasploitV4>`)

	// Write to file
	cf, err := os.Create(fileName)
	if err != nil {
		log.Println("Error writing file: ", err)
	}
	nf, err := io.WriteString(cf, strings.Join(xmlOut, ""))
	if err != nil {
		log.Println("Error writing file: ", nf, err)
	}
	cf.Close()

	return nil
}
