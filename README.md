# ctlog

another certificate transparency log query tool

why another one? crt.sh is really slow. there isn't a good alternative command line tool.

# usage

Install dependencies: `pip3 install -r ./requirements.txt`

Run with param:

```
❯ python3 ./ctlog.py -h
usage: ctlog.py [-h] [--serial SERIAL] [--source {certkit,sslmate}] [--apikey APIKEY] [--include-all] [--dump] [--mate-after MATE_AFTER] domain_name

positional arguments:
  domain_name           domain name that you want to query, to request specific certificate PEM via certkit, set it to 'cert'

options:
  -h, --help            show this help message and exit
  --serial SERIAL       serial number of the certificate
  --source {certkit,sslmate}
                        source of the CT log API
  --apikey APIKEY       API key for the SSLMate CT log API
  --include-all         include subdomains in the SSLMate API query
  --dump                dump raw certificate pem to file, only available in SSLMate (bulk), CertKit (single, via SN)
  --mate-after MATE_AFTER
                        Continuously retrieve CT log after this SSLMate ID, pagination workaround
```

# license

GNU AGPL v3
