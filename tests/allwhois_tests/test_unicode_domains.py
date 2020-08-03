from allwhois import whois


class TestUnicodeDomains:

    def test_no_match(self):
        domain = "нарояци.com"
        result = whois.query(domain)
        assert result["msg"] == "No match"

    def test_parsing_error(self):
        domain = "öbb.at"
        result = whois.query(domain)
        assert result["msg"] == "Err parsing"

