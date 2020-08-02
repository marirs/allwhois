#!/usr/bin/env python
import sys
from allwhois import whois
from pprint import pprint

test_domains = {
    'google': [
        "com", "net", "org", "biz", "com.ua", "com.tr", "com.sa", "com.ua", "com.br", "com.pe",
        "us", "ai", "io", "ca", "uz", "jp", "at", "co", "ee", "tv", "kg", "hn", "am", "by", "kz",
        "mx", "lu", "lv", "cz", "it", "ie", "be", "me", "eu", "ru", "cc", "do", "de", "pl", "fi",
        "fr", "in", "cn",
        "co.ve", "co.cr", "co.id", "co.il", "co.uk", "co.jp",
        "name", "info", "space", "online", "link", "mobi"
    ],
    'northampton': ["ac.uk"],
    'ox': ["ac.uk"],
    'royal': ["uk"],
    'stanford': ["edu"],
    'gov': ["uk", "in", "us"],
    'zomato': ["delivery"],
    'wellsfargo': ['bank'],
    'ican': ['help']
}


def _domain_query(domain: str):
    response = whois.query(domain, date_as_string=True)
    print(f"Query: {domain}")
    pprint(response)
    print("--" * 10)
    print("")
    return response


if __name__ == "__main__":
    try:
        domains = sys.argv[1].split(",")
    except:
        domains = test_domains

    if isinstance(domains, list):
        for domain in domains:
            response = _domain_query(domain)
    else:
        for domain, tlds in domains.items():
            for tld in tlds:
                response = _domain_query(f'{domain}.{tld}')

    print("")
