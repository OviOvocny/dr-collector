"""Self-contained DNS resolver for the collector"""
__author__ = "Adam Horák"

from typing import Tuple, List, Union
import dns.resolver
from config import Config
from datatypes import DNSData
from exceptions import *

class DNS:
  def __init__(self):
    self._dns = dns.resolver.Resolver()
    self._dns.nameservers = Config.DNS_SERVERS

  # query domain for all record types in record_types
  def query(self, domain: str, record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']) -> Tuple[DNSData, Union[List[str], None]]:
    records = {}
    filled = 0
    retry_possible = False
    for record_type in record_types:
      try:
        answer = self._dns.resolve(domain, record_type, lifetime=Config.TIMEOUT)
        records[record_type] = [a.to_text() for a in answer]
        filled += 1
      except dns.resolver.LifetimeTimeout: #type: ignore
        # if we get a timeout, we can retry another time
        retry_possible = True
        records[record_type] = None
      except:
        records[record_type] = None
    # if no records were found, raise an exception
    if filled == 0 and retry_possible:
      raise ResolutionNeedsRetry
    # return records, plus resolved IP4 for convenience
    return DNSData(**records), records.get('A', None)

  # quick query for just the IP address
  def get_ip(self, domain: str, ip6 = False):
    try:
      return self._dns.resolve(domain, 'AAAA' if ip6 else 'A', lifetime=Config.TIMEOUT)
    except:
      return None
    
    
  # Missing modules for collector from Poli
  def get_asn(self, domain: str):
    ip = self.get_ip(domain)
    
    if ip is None:
      return None
    try:
      asn_number = subprocess.check_output(["whois", "-h", "whois.cymru.com", " -v " + ip]).decode("utf-8").split("\n")[1].split("|")[0].strip()
      return asn_number
    except:
      return None
      
    
  def get_ttl(self, domain: str):
    ip = self.get_ip(domain)
    
    if ip is None:
      return None
    
    try:
      ttl = subprocess.check_output(["dig", "+noall", "+answer", "+ttlid", domain]).decode("utf-8").split("\n")[1].split("\t")[1].strip()
      return ttl
    except:
      return None