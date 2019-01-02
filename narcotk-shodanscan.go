package main

import (
	"context"
	_ "encoding/json"
	_ "errors"
	"flag"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/ns3777k/go-shodan.v3/shodan"
)

var myhosts []string
var shodantoken string
var viewdnstoken string

var myips []net.IP

func init() {
	flag.Bool("version", false, "display version information")
	flag.Bool("displayconfig", false, "display configuration")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("ERROR loading config: ", err)
	} else {
		if viper.GetBool("GetTokenFromEnv") == false {
			shodantoken = viper.GetString("ShodanToken")
			viewdnstoken = viper.GetString("ViewDNSToken")
		} else {
			viper.AllowEmptyEnv(true)
			viper.SetEnvPrefix("nss")
			viper.BindEnv("SHODAN")
			viper.BindEnv("VIEWDNS")
			shodantoken = viper.GetString("SHODAN")
			viewdnstoken = viper.GetString("VIEWDNS")
		}
	}

	if viper.GetBool("displayconfig") {
		log.Println("Configuration:")
		for key, value := range viper.AllSettings() {
			log.Println(key, ":", value)
		}
		os.Exit(0)
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

	myhosts = viper.GetStringSlice("Hosts")

	log.Println("Checking Hosts:", myhosts)

	var myhostservices shodan.HostServicesOptions

	for _, specifichost := range myhosts {
		dns, err := client.GetDNSResolve(context.Background(), []string{specifichost})

		var myforward string
		var reverseLookupVal string

		if err != nil {
			log.Println("ERROR doing GetDNSResolve")
			log.Panic(err)
		} else {

			if dns[specifichost] == nil {
				myforward = "NotFound-Forward"
				reverseLookupVal = "NA"
			} else {
				myforward = dns[specifichost].String()

				reverselookup, err := client.GetDNSReverse(context.Background(), []net.IP{*dns[specifichost]})

				if err != nil {
					log.Panic(err)
				} else {
					specificHostDns := reverselookup[dns[specifichost].String()]

					if specificHostDns != nil {
						reverseLookupVal = strings.Join(*specificHostDns, ",")
					} else {
						reverseLookupVal = "NotFound-Reverse"
					}
				}
			}

			log.Println("HOST:", specifichost, "FORWARD:", myforward, "REVERSE:", reverseLookupVal)

			if dns[specifichost] != nil {

				hostdetails, err := client.GetServicesForHost(context.Background(), myforward, &myhostservices)

				if err != nil {
					log.Println("HOST:", specifichost, "WARN:", err)
				} else {
					log.Println("HOST:", specifichost, "OpenPorts:", hostdetails.Ports)
					log.Println("HOST:", specifichost, "Vulnerabilities:", hostdetails.Vulnerabilities)
					log.Println("HOST:", specifichost, "LastUpdate:", hostdetails.LastUpdate)
					log.Println("HOST:", specifichost, "IP:", hostdetails.IP)
					log.Println("HOST:", specifichost, "OS:", hostdetails.OS)
					log.Println("HOST:", specifichost, "Hostnames:", hostdetails.Hostnames)
				}
			} else {
				log.Println("HOST:", specifichost, "WARN: Host details skipped, host not resolvable")
			}
		}
	}
}
