# Narcotk-shodanscan

A simple app that will grab a shodan scan of your IP and save the results in a database.

It can also alert you via syslog, pushover, twitter or email if there is any change.

You will need to sign up for a [shodan.io](https://www.shodan.io/) account and get an API key which is free.

## Usage

1. Run a scan using current IP address:
  
  ```
  # ./narcotk-shodanscan --api myapikey
  ```

1. Run a scan using a specific IP address:

  ```
  # ./narcotk-shodanscan --api myapikey --ip 123.123.123.123
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
