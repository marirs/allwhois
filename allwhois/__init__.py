"""
Query the whois to get domain information
"""
__all__ = ["whois"]

from .query import Query

whois = Query()
