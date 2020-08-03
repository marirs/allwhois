from allwhois import whois
from .results import lookup_results


class TestDomainLookups:

    def test_nonexistant_tld(self):
        domain = "nonexistant.tld"
        result = whois.query(domain, date_as_string=True)
        assert result == lookup_results['nonexistant_tld']

    def test_google_com(self):
        domain = "google.com"
        result = whois.query(domain, date_as_string=True)
        assert result["msg"] == "success"
        assert result["domain_info"]["name"].lower() == "google.com"
        assert result == lookup_results['google_com']

    def test_google_net(self):
        domain = "google.net"
        result = whois.query(domain, date_as_string=True)
        assert result["msg"] == "success"
        assert result["domain_info"]["name"].lower() == "google.net"
        assert result == lookup_results['google_net']

    def test_google_org(self):
        domain = "google.org"
        result = whois.query(domain, date_as_string=True)
        assert result["msg"] == "success"
        assert result["domain_info"]["name"].lower() == "google.org"
        assert result == lookup_results['google_org']

    def test_example_com(self):
        domain = "example.com"
        result = whois.query(domain, date_as_string=True)
        assert result["msg"] == "success"
        assert result["domain_info"]["name"].lower() == "example.com"
        assert result == lookup_results['example_com']

