import pytest
from allwhois import whois


class TestGeneric:

    def test_set_encoding(self):
        whois.encoding = 'ascii'
        assert whois.encoding == 'ascii'

    def test_set_executable(self):
        executable = whois.executable  # get the original executable
        whois.executable = '/usr/bin/whois'  # set a new executable
        assert whois.executable == '/usr/bin/whois'  # check
        whois.executable = executable  # revert back to old executable
        assert whois.executable == executable  # check

    def test_executable_not_found(self):
        executable = whois.executable  # get the original executable
        whois.executable = '/usr/bin/nowhois'
        with pytest.raises(FileNotFoundError):
            whois.query('google.com')
        whois.executable = executable  # revert back to old executable
        assert whois.executable == executable  # check

    def test_incorrect(self):
        executable = whois.executable  # get the original executable
        whois.executable = '/usr/bin/whois'
        with pytest.raises(ValueError):
            whois.query('google.com')
        whois.executable = executable  # revert back to old executable
        assert whois.executable == executable  # check
