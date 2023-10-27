# truffleproxy
HTTP proxy that uses [trufflehog's](https://github.com/trufflesecurity/trufflehog) engine to find credentials. 

## Build

Clone this repo and then run the following commands to build for your current OS:
```bash
# Move into the truffleproxy directory
cd truffleproxy

# Update all the modules
go get -u ./...

# Build the binary
CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath
```

## Certificate

Once the binary is compiled, you can use truffleproxy to to generate certificates.
```bash
./truffleproxy cert   
2023/07/28 12:54:04 Successfully wrote private key: ./truffleproxy.key
2023/07/28 12:54:04 Successfully wrote certificate file: ./truffleproxy.crt
```

Or you could create the certs manually using `openssl`:

```bash
openssl genrsa -out truffleproxy.key 2048
openssl ecparam -genkey -name secp384r1 -out truffleproxy.key
openssl req -new -x509 -sha256 -key truffleproxy.key -out truffleproxy.crt -batch -days 365
```

Once the cert is created, you will need to import the `truffleproxy.crt` file into your browser in order to intercept HTTPS connections.

## Usage

There are a few options you can use when running truffleproxy.

```
HTTP proxy that uses trufflehog's engine to find secrets

Usage:
  truffleproxy [command]

Available Commands:
  cert        Create a new private key and certificate file
  help        Help about any command
  proxy       Start the HTTP proxy
  scan        Scan a single URL
  version     Print the version

Flags:
  -h, --help   help for truffleproxy

Use "truffleproxy [command] --help" for more information about a command.
```

The proxy command has multiple options: 

```bash
Start the HTTP proxy in order to analyze the responses and check for secrets

Usage:
  truffleproxy proxy [flags]

Flags:
  -c, --cert string       Certificate file to use (default "truffleproxy.crt")
  -e, --exclude string    File containing domains to exclude
  -h, --help              help for proxy
  -k, --key string        Key file to use (default "truffleproxy.key")
  -l, --logfile string    Log file to write to (default: none)
  -o, --only-verified     Only output secrets that were verified
  -p, --port int          Proxy port to listen on (default 9090)
  -s, --scanners string   Specify the scanners to use in a comma separated list (default all)
  -b, --verbose           Output all URLs that are being scanned not just ones identified as having secrets
  -v, --verify            Verified identified secrets
```

You can run the following command to start the proxy on the default port (9090), verify secrets it identifies, and skip checking certain domains.

```bash
./truffleproxy proxy --verify --exclude excludedomains.txt
```

The excludedomains.txt file contains a list of domains to skip
```
amazon.com
apple.com
doubleclick.net
duckduckgo.com
google.com
googleapis.com
gstatic.com
microsoft.com
netflix.com
youtube.com
```

## Sample data

Below are a few repos that contain sample keys/credentials you can test with.

- https://raw.githubusercontent.com/trufflesecurity/test_keys/main/keys
- https://raw.githubusercontent.com/sourcegraph-community/no-secrets/main/secret-examples.md

You can see truffleproxy identifies the secrets when browsing the the pages through the proxy. It also returns "verified" as "false", stating that the key is not valid.

```bash
./truffleproxy proxy --verify --exclude excludedomains.txt 
{"level":"info","timestamp":"2023-08-07 21:44:37.465","msg":"started truffleproxy"}
{"level":"info","timestamp":"2023-08-07 21:44:37.465","msg":"loaded certificate and key file"}
{"level":"info","timestamp":"2023-08-07 21:44:37.465","msg":"loaded domains to exclude","domains_loaded":10}
{"level":"info","timestamp":"2023-08-07 21:44:37.466","msg":"loaded scanners","num_scanners":748}
{"level":"info","timestamp":"2023-08-07 21:44:37.466","msg":"verify secrets","verify":true}
{"level":"info","timestamp":"2023-08-07 21:44:37.466","msg":"verbose output","verbose":false}
{"level":"info","timestamp":"2023-08-07 21:44:37.466","msg":"starting proxy server","address":":9090"}
{"level":"warn","timestamp":"2023-08-07 21:44:55.463","msg":"secrets found","url":"https://raw.githubusercontent.com:443/sourcegraph-community/no-secrets/main/secret-examples.md","scanner":"aws","value":"AKIA01JDFHS8CDS82AAA","verified":false}
{"level":"warn","timestamp":"2023-08-07 21:44:55.463","msg":"secrets found","url":"https://raw.githubusercontent.com:443/sourcegraph-community/no-secrets/main/secret-examples.md","scanner":"aws","value":"AKIA01JDFHS8CDS82AAAJzXPbtuH2I26L5ilEziVM18Ecd1EW0t2AIjaJIht","verified":false}
{"level":"warn","timestamp":"2023-08-07 21:44:55.463","msg":"secrets found","url":"https://raw.githubusercontent.com:443/sourcegraph-community/no-secrets/main/secret-examples.md","scanner":"github","value":"ghp_q6yv2mqrgewsuuvzcvqldsi4detvof4r5bse","verified":false}
{"level":"warn","timestamp":"2023-08-07 21:44:55.463","msg":"secrets found","url":"https://raw.githubusercontent.com:443/sourcegraph-community/no-secrets/main/secret-examples.md","scanner":"mailchimp","value":"e3a648d99c398572dec8a7650c92d1c0-us16","verified":false}
{"level":"warn","timestamp":"2023-08-07 21:44:55.463","msg":"secrets found","url":"https://raw.githubusercontent.com:443/sourcegraph-community/no-secrets/main/secret-examples.md","scanner":"stripe","value":"rk_live_WXMzpZg9ueNeYNsKhDmQW6Yj","verified":false}
{"level":"warn","timestamp":"2023-08-07 21:44:55.463","msg":"secrets found","url":"https://raw.githubusercontent.com:443/sourcegraph-community/no-secrets/main/secret-examples.md","scanner":"mailgun","value":"key-06b34653fd57060f62e4475450ccf053","verified":false}
```

## Disclaimer

This tool should be considered research and should not be used maliciously. Any identified secrets should be properly disclosed to the owner. The author does not take responsibility for it's use.

## Credits

I wanted to give credit to [trufflehog](https://github.com/trufflesecurity/trufflehog) for initially creating their tool and all of the contributors who have added the different secret detectors.
