All Whois
============

[![Build Status](https://travis-ci.org/marirs/allwhois.svg?branch=master)](https://travis-ci.org/marirs/allwhois)
[![codecov](https://codecov.io/gh/marirs/allwhois/branch/master/graph/badge.svg)](https://codecov.io/gh/marirs/allwhois)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-orange)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/quart-motor)
[![GitHub license](https://img.shields.io/github/license/marirs/allwhois)](https://github.com/marirs/allwhois/blob/master/LICENSE)

A Python package for retrieving WHOIS information of domains.

#### Description/Features

- Python wrapper for Linux "`whois`" command
- Get `parsed` & `raw` WHOIS data for a given domain
- Extract data for `any` TLD.
- No TLD regex's
- Date's as `datetime objects` or `strings`
- Caching of results

#### Requirements

- Python 3.6+

Support for python 3.6+ only. Works on `macos` & `linux` only

#### Issues

If there is something that is not parsing well, open a issue, and i will look into it.
Or if you fixed it, do make a pull request, and i can merge it.

#### Installation

```bash
pip install allwhois
```

#### Pre-requisite installation

- macOS
```bash
brew install whois
```

- Linux
```bash
apt install whois
```

#### Usage

```python
import sys
from allwhois import whois
from pprint import pprint

if __name__ == "__main__":
    domain = None
    try:
        domain = sys.argv[1]
    except:
        exit(f"Usage: {sys.argv[0]}  <domain_name>")

    response = whois.query(domain)
    pprint(response)
```

---
Authors:
- Sriram: [marirs](http://github.com/marirs)
