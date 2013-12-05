package main

import (
	"crypto/tls"
	"github.com/docopt/docopt.go"
	"github.com/tomsteele/golair"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"log"
	"net"
	"net/url"
	"os"
	"time"
)

// Uses TLS to connect to a MongoDb instance.
func TLSDial(addr net.Addr) (net.Conn, error) {
	return tls.Dial(addr.Network(), addr.String(), &tls.Config{InsecureSkipVerify: true})
}

func main() {
	arguments, err := docopt.Parse(usage, nil, true, "drone-msf 0.1", false)
	if err != nil {
		log.Fatal("Error parsing usage. Error: ", err.Error())
	}

	murl := os.Getenv("MONGO_URL")
	if murl == "" {
		log.Fatal("MONGO_URL environment varable not set")
	}
	u, err := url.Parse(murl)
	if err != nil {
		log.Fatal("Error parsing MONGO_URL", err.Error())
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		log.Fatal("Error parsing query parameters", err.Error())
	}

	lpid := arguments["<lpid>"].(string)
	f := arguments["<file>"].(string)
	imp := arguments["import"].(bool)
	exp := arguments["export"].(bool)

	db := u.Path[1:]
	s := &mgo.Session{}

	if opt, ok := q["ssl"]; ok && opt[0] == "true" {
		var user, pass string
		if u.User != nil {
			user = u.User.Username()
			p, set := u.User.Password()
			if set {
				pass = p
			}
		}
		d := &mgo.DialInfo{
			Addrs:    []string{u.Host},
			Direct:   true,
			Database: db,
			Username: user,
			Password: pass,
			Dial:     TLSDial,
			Timeout:  time.Duration(10) * time.Second,
		}
		s, err = mgo.DialWithInfo(d)
		if err != nil {
			log.Fatal("Could not connect to database. Error: ", err.Error())
		}
	} else {
		s, err = mgo.Dial(murl)
		if err != nil {
			log.Fatal("Could not connect to database. Error: ", err.Error())
		}
	}

	c := s.DB(db).C("projects")
	p := golair.Project{}
	err = c.Find(bson.M{"_id": lpid}).Select(bson.M{"_id": 1}).One(&p)
	if err != nil {
		log.Fatal("Could not find a project with that id. Error: ", err.Error())
	}

	if imp {
		nh := arguments["--no-hosts"].(bool)
		nc := arguments["--no-creds"].(bool)
		// TODO: Build list of valid scope
		scope := []string{}
		err = msfImport(s, lpid, f, scope, nh, nc)
		if err != nil {
			log.Fatal("Error importing into Lair. Error: ", err.Error())
		}
	}

	if exp {
		err = msfExport(s, lpid, f)
		if err != nil {
			log.Fatal("Error exporting from Lair. Error: ", err.Error())
		}
	}
}
