package main

import (
	"context"
	_ "encoding/json"
	_ "errors"
	"flag"
	"fmt"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log"
	"net"
	"os"
	"sort"
	"strings"

	"gopkg.in/ns3777k/go-shodan.v3/shodan"
)

const appversion = 0.01

var myhosts []string
var shodantoken string
var viewdnstoken string

var myips []net.IP

func init() {
	configFile := flag.String("config", "", "name of configuration file")
	configFilePath := flag.String("configpath", "", "path to configuration file")
	flag.Bool("current", false, "scan current visibly external IP")
	flag.Bool("displayconfig", false, "display configuration")
	flag.Bool("help", false, "display help")
	flag.String("scan", "", "host(s) to scan")
	flag.Bool("version", false, "display version information")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	if *configFilePath == "" {
		viper.AddConfigPath(".")
	} else {
		viper.AddConfigPath(*configFilePath)
	}

	if *configFile == "" {
		viper.SetConfigName("config")
	} else {
		viper.SetConfigName(*configFile)
	}

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

		if len(viper.GetString("scan")) != 0 {
			myhosts = append(myhosts, strings.Split(viper.GetString("scan"), ",")...)
		} else {
			myhosts = viper.GetStringSlice("Hosts")
		}

	}

	if viper.GetBool("help") {
		displayHelp()
		os.Exit(0)
	}

	if viper.GetBool("version") {
		fmt.Println(appversion)
		os.Exit(0)
	}

	if viper.GetBool("displayconfig") {
		displayConfig()
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

	if viper.GetBool("current") {
		myhosts = nil
		myhosts = append(myhosts, myip.String())
	}

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
					log.Println("HOST:", specifichost, "OPENPORTS:", hostdetails.Ports)
					log.Println("HOST:", specifichost, "VULNERABILITIES:", hostdetails.Vulnerabilities)
					log.Println("HOST:", specifichost, "LASTUPDATE:", hostdetails.LastUpdate)
					log.Println("HOST:", specifichost, "IP:", hostdetails.IP)
					log.Println("HOST:", specifichost, "OS:", hostdetails.OS)
					log.Println("HOST:", specifichost, "HOSTNAMES:", hostdetails.Hostnames)
				}
			} else {
				log.Println("HOST:", specifichost, "WARN: Host details skipped, host not resolvable")
			}
		}
	}
}

func displayConfig() {
	fmt.Println("CONFIG: file :", viper.ConfigFileUsed())
	allmysettings := viper.AllSettings()
	var keys []string
	for k := range allmysettings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println("CONFIG:", k, ":", allmysettings[k])
	}
}

func displayHelp() {
	fmt.Println("--config                            Configuration file --config myconfig.yaml")
	fmt.Println("--configpath                        Path to configuration file --configpath /path/to")
	fmt.Println("--current                           Scan current externally visible IP")
	fmt.Println("--displayconfig                     Display configuration")
	fmt.Println("--scan                              Scan these hosts --scan host1.com,host2.com,8.8.8.8")
	fmt.Println("--version                           Version")
}
