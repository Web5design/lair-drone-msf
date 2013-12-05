package main

import (
	"encoding/xml"
	"fmt"
	"github.com/tomsteele/golair"
	"io/ioutil"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"log"
	"net"
	"strings"
)

type MsfXML struct {
	XMLName xml.Name `xml:"MetasploitV4"`
	Hosts   []Host   `xml:"hosts>host"`
}

type Host struct {
	XMLName  xml.Name  `xml:"host"`
	Address  string    `xml:"address"`
	Mac      string    `xml:"mac"`
	Name     string    `xml:"name"`
	State    string    `xml:"state"`
	OsName   string    `xml:"os-name"`
	OsFlavor string    `xml:"os-flavor"`
	OsSp     string    `xml:"os-sp"`
	Services []Service `xml:"services>service"`
	Creds    []Cred    `xml:"creds>cred"`
}

type Service struct {
	XMLName xml.Name `xml:"service"`
	Port    int      `xml:"port"`
	Proto   string   `xml:"proto"`
	State   string   `xml:"state"`
	Name    string   `xml:"name"`
	Info    string   `xml:"info"`
}

type Cred struct {
	Port   int    `xml:"port"`
	User   string `xml:"user"`
	Pass   string `xml:"pass"`
	Active bool   `xml:"active"`
}

func msfImport(s *mgo.Session, lpid, fileName string, scope []string, nh bool, nc bool) error {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}
	var m MsfXML
	err = xml.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	hc := s.DB("").C("hosts")
	pc := s.DB("").C("ports")

	for _, host := range m.Hosts {
		if host.State != "alive" {
			continue
		}
		lhost, err := golair.NewHost(lpid, host.Address, "Metasploit")
		if err != nil {
			return err
		}
		lhost.MacAddr = host.Mac
		// Make sure name from metasploit is not an IP.
		if net.ParseIP(host.Name) == nil {
			lhost.Hostnames = append(lhost.Hostnames, host.Name)
		}
		if host.OsName != "Unknown" && host.OsName != "" {
			os := strings.TrimSpace(fmt.Sprintf("%s %s %s", host.OsName, host.OsFlavor, host.OsSp))
			lhost.Os = append(lhost.Os, golair.Os{Tool: "Metasploit", Weight: 80, Fingerprint: os})
		}
		change := mgo.Change{
			Update: bson.M{
				"$addToSet": bson.M{
					"hostnames": bson.M{"$each": lhost.Hostnames},
					"os":        bson.M{"$each": lhost.Os},
				},
				"$set": bson.M{
					"last_modified_by": lhost.LastModifiedBy,
					"mac_addr":         lhost.MacAddr,
				},
				"$setOnInsert": bson.M{
					"notes":  lhost.Notes,
					"alive":  true,
					"status": lhost.Status,
					"flag":   lhost.Flag,
				},
			},
			Upsert:    true,
			ReturnNew: true,
		}
		q := bson.M{"project_id": lpid, "string_addr": lhost.StringAddr}
		// There is an extra query here and likely below to make this code work with Mongodb 2.4.
		// https://jira.mongodb.org/browsfe/SERVER-9958
		dHost := &golair.Host{}
		err = hc.Find(q).One(&dHost)
		if err != nil {
			log.Println("Creating host ", lhost.StringAddr)
			q["_id"] = lhost.ID
		}
		_, err = hc.Find(q).Apply(change, &dHost)
		if err != nil {
			return err
		}
		// Import services for each host.
		for _, service := range host.Services {
			if service.State != "open" {
				continue
			}
			lport, err := golair.NewPort(lpid, dHost.ID, service.Port, "Metasploit")
			if err != nil {
				return nil
			}
			lport.Protocol = service.Proto
			set := make(map[string]string)
			setOnInsert := make(map[string]interface{})
			set["last_modified_by"] = lport.LastModifiedBy
			set["protocol"] = lport.Protocol
			setOnInsert["notes"] = lport.Notes
			setOnInsert["alive"] = lport.Alive
			setOnInsert["status"] = lport.Status
			setOnInsert["flag"] = lport.Flag
			if service.Name != "Unknown" && service.Name != "" {
				set["service"] = service.Name
			} else {
				setOnInsert["service"] = lport.Service
			}
			if service.Info != "Unknown" && service.Info != "" {
				set["product"] = service.Info
			} else {
				set["product"] = lport.Product
			}
			pup := bson.M{
				"$set":         set,
				"$setOnInsert": setOnInsert,
			}
			change = mgo.Change{
				Update:    pup,
				Upsert:    true,
				ReturnNew: true,
			}
			q = bson.M{"project_id": lpid, "host_id": dHost.ID, "port": lport.Port}
			dPort := &golair.Port{}
			err = pc.Find(q).One(&dPort)
			if err != nil {
				q["_id"] = lport.ID
			}
			_, err = pc.Find(q).Apply(change, &dPort)
			if err != nil {
				return err
			}

		}
		for _, cred := range host.Creds {
			c := &golair.Credential{Username: cred.User, Password: cred.Pass}
			err = pc.Update(bson.M{"project_id": lpid, "port": cred.Port}, bson.M{"$addToSet": bson.M{"credentials": c}})
			if err != nil {
				log.Printf("Could not add credential %s %s\n", cred.User, cred.Pass)
			}
		}
	}
	return nil
}
