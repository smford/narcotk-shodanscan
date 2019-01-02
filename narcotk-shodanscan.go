package main

import (
	"context"
	_ "encoding/json"
	_ "errors"
	"flag"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os"
	//"fmt"
	"log"
	"net"
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
			log.Println("ShodanToken:", shodantoken)
			log.Println("ViewDNSToken:", viewdnstoken)
		} else {
			log.Println("Reading tokens from environment variables NSS_SHODAN and NSS_VIEWDNS")
			viper.AllowEmptyEnv(true)
			viper.SetEnvPrefix("nss")
			viper.BindEnv("SHODAN")
			viper.BindEnv("VIEWDNS")
			//log.Println("env shodan =", viper.Get("SHODAN"))
			shodantoken = viper.GetString("SHODAN")
			//log.Println("env viewdns =", viper.Get("VIEWDNS"))
			viewdnstoken = viper.GetString("VIEWDNS")
		}
	}

	if viper.GetBool("displayconfig") {
		//log.Println("Configuration:\n", viper.AllSettings())
		log.Println("Configuration:")
		for key, value := range viper.AllSettings() {
			log.Println(key, ":", value)
		}
		os.Exit(0)
	}

}

func main() {
	log.Println("start---------------------")
	for _, confighost := range viper.GetStringSlice("Hosts") {
		log.Println("host=", confighost)
	}

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

	//myhosts = append(myhosts, "narco.tk")
	//myhosts = append(myhosts, "stephenford.org")
	//myhosts = append(myhosts, "narcotk.myqnapcloud.com")
	//myhosts = append(myhosts, "narcotk.myqnapcloud.com", "epilep.tk", "narco.tk", "stephenford.org", "bleh.co.nz", "ftp.geek.nz")
	//myhosts = append(myhosts, "narcotk.myqnapcloud.com", "epilep.tk", "narco.tk", "bleh.co.nz", "ftp.geek.nz")
	//myhosts = append(myhosts, "narcotk.myqnapcloud.com", "epilep.tk")
	log.Println("Checking Hosts:", myhosts)

	var myhostservices shodan.HostServicesOptions

	for _, specifichost := range myhosts {
		//log.Println("Starting:", specifichost)
		dns, err := client.GetDNSResolve(context.Background(), []string{specifichost})

		var myforward string
		var reverseLookupVal string

		if err != nil {
			log.Println("ERROR doing GetDNSResolve")
			log.Panic(err)
		} else {

			//log.Println("checking forward lookup ===========")
			if dns[specifichost] == nil {
				//log.Println("forward not found")
				myforward = "NotFound-Forward"
				reverseLookupVal = "NA"
			} else {
				//log.Println("Forward lookup success")
				myforward = dns[specifichost].String()

				//log.Println("Starting reverse lookup")
				reverselookup, err := client.GetDNSReverse(context.Background(), []net.IP{*dns[specifichost]})

				if err != nil {
					log.Panic(err)
				} else {
					specificHostDns := reverselookup[dns[specifichost].String()]

					//var reverseLookupVal string
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
