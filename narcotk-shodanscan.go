package main

import (
	"context"
	_ "encoding/json"
	_ "errors"
	"flag"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	//"fmt"
	"log"
	"net"

	"gopkg.in/ns3777k/go-shodan.v3/shodan"
)

var myhosts []string
var shodantoken string
var viewdnstoken string

var myips []net.IP

func init() {
	flag.Bool("version", false, "display version information")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigName("narcotk-shodanscan")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("ERROR loading config: ", err)
	} else {
		shodantoken = viper.GetString("ShodanToken")
		viewdnstoken = viper.GetString("ViewDNSToken")
		log.Println("ShodanToken:", shodantoken)
		log.Println("ViewDNSToken:", viewdnstoken)
		shodantoken = viper.GetString("ShodanToken")
		viewdnstoken = viper.GetString("ViewDNSToken")
	}
}

func main() {
	// Start up a connection to shodan
	client := shodan.NewClient(nil, shodantoken)

	// Print my current IP
	myip, err := client.GetMyIP(context.Background())
	if err != nil {
		log.Panic(err)
	} else {
		log.Println("Current IP: ", myip)
	}

	//myhosts = append(myhosts, "narcotk.myqnapcloud.com", "epilep.tk", "narco.tk", "stephenford.org", "bleh.co.nz", "ftp.geek.nz")
	myhosts = append(myhosts, "narcotk.myqnapcloud.com", "epilep.tk", "narco.tk", "bleh.co.nz", "ftp.geek.nz")
	//myhosts = append(myhosts, "narcotk.myqnapcloud.com", "epilep.tk")
	log.Println("Checking Hosts:", myhosts)

	var myhostservices shodan.HostServicesOptions

	for _, specifichost := range myhosts {
		log.Println("Starting:", specifichost)
		//log.Println("--------")
		//log.Println("Checking: ", specifichost)
		dns, err := client.GetDNSResolve(context.Background(), []string{specifichost})
		if err != nil {
			log.Println("Error found when doing forward lookup")
			//log.Panic(err)
		} else {
			//log.Println("Host:", specifichost, " FORWARD:", dns[specifichost])
			//ipv4Addr, ipv4Net, err := net.ParseCIDR(dns[specifichost])
			//var mynetworkips net.IP = dns[specifichost]
			//mystringip := Key(dns[specifichost])
			//mynetip := net.ParseIP(mystringip)
			//myips = append(myips, mynetip)
			//log.Println("myips = ", myips)
			//var mytempip net.IP
			//mytempip = *dns[specifichost]

			//reverselookup, err := client.GetDNSReverse(context.Background(), []net.IP{dns[specifichost]})

			//log.Println("before")
			var myforward string

			if dns[specifichost].String() == "" {
				log.Println("stuff is nil")
			}
			//log.Println("after")

			//if myforward == "" {
			//	myforward = "BLANK"
			//}

			myforward = dns[specifichost].String()

			reverselookup, err := client.GetDNSReverse(context.Background(), []net.IP{*dns[specifichost]})

			if err != nil {
				log.Panic(err)
			} else {
				//log.Println("HOST:", specifichost, " FORWARD:", dns[specifichost], " REVERSE:", reverselookup[dns[specifichost]])
				// WORKING: log.Println("HOST:", specifichost, " FORWARD:", dns[specifichost], " REVERSE:", reverselookup[KeyString(*dns[specifichost])])
				//log.Println("HOST:", specifichost, " FORWARD:", dns[specifichost], " REVERSE:", reverselookup[KeyString(*dns[specifichost])])

				//var myforward string = dns[specifichost].String()
				//
				//if myforward == "" {
				//	myforward = "BLANK"
				//}

				//var myreverse string = reverselookup[dns[specifichost].String()]
				//log.Println("HOST:", specifichost, " FORWARD:", dns[specifichost], " REVERSE:", reverselookup[dns[specifichost].String()])
				log.Println("HOST:", specifichost, "FORWARD:", myforward, "REVERSE:", reverselookup[dns[specifichost].String()])

				hostdetails, err := client.GetServicesForHost(context.Background(), myforward, &myhostservices)

				if err != nil {
					log.Println("HOST:", specifichost, "ERROR WHEN ATTEMPTING TO SCAN", specifichost, "on ", myforward, ":", err)
				} else {
					log.Println("HOST:", specifichost, "OpenPorts:", hostdetails.Ports)
					log.Println("HOST:", specifichost, "Vulnerabilities:", hostdetails.Vulnerabilities)
					log.Println("HOST:", specifichost, "LastUpdate:", hostdetails.LastUpdate)
					log.Println("HOST:", specifichost, "IP:", hostdetails.IP)
					log.Println("HOST:", specifichost, "OS:", hostdetails.OS)
					log.Println("HOST:", specifichost, "Hostnames:", hostdetails.Hostnames)
				}
			}

		}
		//log.Println("========")
	}
}

func KeyString(ip net.IP) string {
	//fmt.Printf("=", string(ip.String()), "=")
	return string(ip.String()) // Simple []byte => string conversion
}
