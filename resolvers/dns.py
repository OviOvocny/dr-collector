"""Self-contained DNS resolver for the collector"""
__author__ = "Adam Horák"

import dns.resolver
from config import Config
from datatypes import DNSData

class DNS:
  def __init__(self):
    self._dns = dns.resolver.Resolver()
    self._dns.nameservers = Config.DNS_SERVERS

  # query domain for all record types in record_types
  def query(self, domain: str, record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']):
    records = {}
    for record_type in record_types:
      try:
        answer = self._dns.resolve(domain, record_type, lifetime=Config.TIMEOUT)
        records[record_type] = [a.to_text() for a in answer]
      except:
        records[record_type] = None
    # return records, plus resolved IP4 for convenience
    return DNSData(**records), records.get('A', None)

  # quick query for just the IP address
  def get_ip(self, domain: str, ip6 = False):
    try:
      return self._dns.resolve(domain, 'AAAA' if ip6 else 'A', lifetime=Config.TIMEOUT)
    except:
      return None