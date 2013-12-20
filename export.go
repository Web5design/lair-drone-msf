package main

import (
	"github.com/tomsteele/golair"
	"io"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"os"
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
	xmlOut = append(xmlOut, `<hosts>`)

	s.DB("").C("hosts").Find(bson.M{"project_id": lpid}).All(&hosts)
	for _, host := range hosts {
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

		// Empty Notes and Vulns section. Open creds.
		xmlOut = append(xmlOut, `</services><notes></notes><vulns></vulns><creds>`)

		// Creds section
		// Have to loop by port because lair stores creds based on port, can probably do this easier
		// also need to add logic to add the password OR hash value, not just the password.
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

	// Write to file.
	cf, err := os.Create(fileName)
	defer cf.Close()
	if err != nil {
		return err
	}
	_, err = io.WriteString(cf, strings.Join(xmlOut, ""))
	if err != nil {
		return err
	}
	return nil
}
