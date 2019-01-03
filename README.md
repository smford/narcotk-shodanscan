# Narcotk-shodanscan

A simple app that will run a shodan scan of a host and report back the results.

It is useful to run as a cronjob to discern whether there have been any unexpected changes or new vulnerabilities that effect your systems.

Written in Go, so can run happily in linux, Windows or OSX.

## Requirements

You will need to sign up (free) for [shodan.io](https://www.shodan.io/) and [viewdns.info](https://viewdns.info/api/#register) accounts to get an API keys.


## Features

- Forward lookups
- Reverse lookups
- Vulnerabilities detected with CVE reporting
- External IP reporting
- Discovered open ports
- OS
- Other known hostnames that resolve to that IP

## Coming Features

- Unexpected change detection and alerting
- Integration with syslog
- Alerting via twitter, pushover, email, etc
- Results being saved to a database
- DNS propogation checking
- Spam database inclusion
- Print all dns records


## Usage

1. Run a scan using current IP address:
  
  ```
  # ./narcotk-shodanscan --current
  ```

1. Run a scan against specific hosts:

  ```
  # ./narcotk-shodanscan --scan www.host1.com,host2.net,123.123.123.123
  ```

## Installation

### From Docker


### From git

Requirements:
- go v1.9.10
- dep v0.4.1

  ```
  git clone git@gitlab.com:narcotk/narcotk-shodanscan.git 
  cd narcotk-shodanscan
  dep ensure
  go build
  ./narcotk-showdanscan
  ```


## Configuration File

File: config.yaml

```
GetTokenFromEnv: false
ShodanToken: myApiTokenFromShodan
ViewDNSToken: myApiTokenFromViewDNS
Hosts:
- my.secret.hostname.com
- somedomain.com
- google.com

```
