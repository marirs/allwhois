from allwhois import whois
from datetime import datetime


class TestDates:

    def test_datetime_object(self):
        domain = "google.com"
        result = whois.query(domain)
        assert isinstance(result["domain_info"]["created_date"], datetime)

    def test_datetime_as_string(self):
        domain = "google.com"
        result = whois.query(domain, date_as_string=True)
        assert isinstance(result["domain_info"]["created_date"], str)
