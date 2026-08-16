#!/usr/bin/env python3
#
# Why another certificate transparency log query tool? because crt.sh is sucked slow and unstable, unreliable!

__author__ = "Patrick Young"
__version__ = "2026.08.16"

import requests
import argparse
import logging
import os
from tabulate import tabulate

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(funcName)s L%(lineno)d - %(message)s",
    level=logging.INFO,
)

httpcli = requests.Session()
httpcli.headers.update(
    {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "DNT": "1",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
)

certkit_headers = {
    "Origin": "https://www.certkit.io",
    "Referer": "https://www.certkit.io/",
}


def query_to_sslmate(domain_name, apikey, include_sub, after_id):
    full_qparam = {
        "domain": domain_name,
        "match_wildcards": "true",
        "expand": ["cert_der", "revocation", "issuer", "dns_names"],
        "include_subdomains": include_sub
    }
    final_header = {"Authorization": "Bearer " + apikey}
    if apikey == "":
        final_header = {}
        # rate limit: free: 100 single-domain req/hr, 10 full-domain req/hr
    if after_id:
        full_qparam["after"] = str(after_id)
    # https://api.certspotter.com/v1/issuances?domain=example.com&expand=dns_names&expand=issuer&expand=revocation&expand=cert_der
    req1_search = httpcli.get(
        "https://api.certspotter.com/v1/issuances",
        params=full_qparam,
        headers=final_header,
    )
    req1_search.raise_for_status()
    resp = req1_search.json()
    return resp


def query_to_certkit(domain_name):
    req1_search = httpcli.post(
        "https://ct.certkit.io/search",
        headers=certkit_headers,
        json={"domain": domain_name, "sort": ""},
    )
    req1_search.raise_for_status()
    if req1_search.status_code == 200:
        logging.debug(req1_search.text)
        return req1_search.json()
    return {}


def get_cert_details_from_certkit(serial_num_of_cert):
    req2_detail = httpcli.get(
        f"https://ct.certkit.io/certificate/serial/{serial_num_of_cert}",
        headers=certkit_headers,
    )
    req2_detail.raise_for_status()
    if req2_detail.status_code == 200:
        logging.debug(req2_detail.text)
        try:
            certdata = req2_detail.json()["certificate"]
            print("Is Pre-Certificate: {}".format(certdata["isPrecert"]))
            print(
                "Certificate Public Key Algorithm: {}".format(
                    certdata["publicKeyAlgorithm"]
                )
            )
            dump_cert_pem(certdata["serialNumber"], certdata["pem"], False)
        except KeyError:
            logging.error(
                "Failed to retrieve certificate details from certkit API, missing PEM."
            )
    return


def parse_sslmate_resp(response, must_dump):
    if len(response) == 0:
        logging.info("No certificate found in SSLMate API response.")
        return []
    else:
        logging.info("Found {} certificates in SSLMate API response.".format(len(response)))
        logging.info("To retrieve all certificates, call again with param: --mate-after {} ".format(response[-1]["id"]))
        # ["SSLMate ID", "Certificate Fingerprint", "Domain Name", "Signed By", "Not Before", "Expiry", "IsRevoked"]
        all_certs = []
        for cert in response:
            if must_dump:
                dump_cert_pem(cert["id"], cert["cert_der"], True)
            all_certs.append(
                [
                    cert["id"],
                    cert["cert_sha256"],
                    cert["dns_names"],
                    cert["issuer"]["name"],
                    cert["not_before"],
                    cert["not_after"],
                    cert["revoked"],
                ]
            )
        return all_certs


def dump_cert_pem(cert_id, cert_pem, fix_header):
    os.makedirs("dumps", exist_ok=True)
    with open("dumps/" + cert_id + "_C.crt", "w") as f:
        if fix_header:
            f.write("-----BEGIN CERTIFICATE-----\n")
        f.write(cert_pem)
        if fix_header:
            f.write("\n-----END CERTIFICATE-----\n")
    logging.info("Certificate dumped to file: dumps/{}".format(cert_id + "_C.crt"))


def parse_certkit_resp(response):
    try:
        if response["totalCount"] == 0:
            return []
        else:
            logging.info("Total certs found: {}".format(response["totalCount"]))
            certs = response["results"]
            all_certs = []
            for cert in certs:
                doms = list({cert["commonName"]} | set(cert["dnsNames"]))
                signedBy = cert["issuerOrganization"]
                signedAt = cert["notBefore"]
                expireAt = cert["notAfter"]
                isPreCert = cert["isPrecert"]
                serialNo = cert["serialNumber"]
                all_certs.append(
                    [serialNo, doms, signedBy, signedAt, expireAt, isPreCert]
                )
            return all_certs
    except KeyError:
        return []


def call_ct_api(args):
    if args.source == "certkit":
        logging.info("Calling certkit API")
        if args.serial:
            logging.info(
                "Requesting specific certificate detail via certkit, serial number: {}".format(
                    args.serial
                )
            )
            get_cert_details_from_certkit(args.serial)
            return
        logging.info(
            "Requesting all related certificates via certkit, domain name: {}".format(
                args.domain_name
            )
        )
        all_certs = query_to_certkit(args.domain_name)
        parsed_certs = parse_certkit_resp(all_certs)
        print("\n")
        print(
            tabulate(
                parsed_certs,
                headers=[
                    "Serial Number",
                    "Domain Name",
                    "Signed By",
                    "Not Before",
                    "Expiry",
                    "Is Pre-Cert",
                ],
            )
        )
    elif args.source == "sslmate":
        logging.info("Calling sslmate API")
        logging.info("Requesting CT Log of domain: {} , include subdomains: {}".format(args.domain_name, args.include_all))
        resp_certs = query_to_sslmate(args.domain_name, args.apikey, args.include_all, args.mate_after)
        parsed_certs = parse_sslmate_resp(resp_certs, args.dump)
        print("\n")
        print(
            tabulate(
                parsed_certs,
                headers=[
                    "SSLMate ID",
                    "Certificate Fingerprint",
                    "Domain Name",
                    "Signed By",
                    "Not Before",
                    "Expiry",
                    "IsRevoked",
                ],
            )
        )
        return
    else:
        raise ValueError("Invalid source")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "domain_name",
        type=str,
        help="domain name that you want to query, to request specific certificate PEM via certkit, set it to 'cert' ",
    )
    parser.add_argument("--serial", type=str, help="serial number of the certificate")
    parser.add_argument(
        "--source",
        type=str,
        required=False,
        default="certkit",
        choices=["certkit", "sslmate"],
        help="source of the CT log API",
    )
    parser.add_argument(
        "--apikey",
        type=str,
        required=False,
        default=os.environ.get("SSLMATE_CTLOG_APIKEY", ""),
        help="API key for the SSLMate CT log API",
    )
    parser.add_argument(
        "--include-all",
        action="store_true",
        required=False,
        default=False,
        help="include subdomains in the SSLMate API query",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        required=False,
        default=False,
        help="dump raw certificate pem to file, only available in SSLMate (bulk), CertKit (single, via SN)",
    )
    parser.add_argument("--mate-after", type=int, required=False, help="Continuously retrieve CT log after this SSLMate ID, pagination workaround")
    args = parser.parse_args()
    if args.dump:
        logging.info("Detected dump-to-file flag is set, afterwards, you may try to run 'openssl x509 -in ./dumps/xxx_C.crt -noout -text' to parse further.")
    call_ct_api(args)


if __name__ == "__main__":
    main()
