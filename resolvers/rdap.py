"""Self-contained RDAP/WHOIS resolver for the collector, wraps whoisit module with auto bootstrapping"""
__author__ = "Adam Horák"

import whoisit
import json
from datatypes import RDAPDomainData, RDAPIPData, RDAPASNData, RDAPEntityData

class RDAP:
  def __init__(self):
    if not whoisit.is_bootstrapped():
      load_bootstrap_data()

  def domain(self, domain: str, **kwargs) -> RDAPDomainData:
    return whoisit.domain(domain, **kwargs)

  def ip(self, ip: str, **kwargs) -> RDAPIPData:
    return whoisit.ip(ip, **kwargs)

  def asn(self, asn: int, **kwargs) -> RDAPASNData:
    return whoisit.asn(asn, **kwargs)

  def entity(self, entity: str, **kwargs) -> RDAPEntityData:
    return whoisit.entity(entity, **kwargs)


def save_bootstrap_data():
  bootstrap_data = whoisit.save_bootstrap_data()
  with open('data/rdap_bootstrap.json', 'w') as f:
    json.dump(bootstrap_data, f)

def bootstrap():
  whoisit.clear_bootstrapping()
  whoisit.bootstrap(overrides=True)
  save_bootstrap_data()

def load_bootstrap_data():
  try:
    with open('data/rdap_bootstrap.json', 'r') as f:
      bootstrap_data = json.load(f)
      whoisit.load_bootstrap_data(bootstrap_data)
      print('Loaded bootstrap data from file')
      if whoisit.bootstrap_is_older_than(3):
        print('Bootstrap data is older than 3 days, bootstrapping...')
        bootstrap()
  except:
    bootstrap()