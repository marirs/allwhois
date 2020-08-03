import pytest
from .allwhois_tests import TestUnicodeDomains, TestDomainLookups, TestDates

if __name__ == '__main__':
    pytest.main(['--color=auto', '--cov', '-v'])
