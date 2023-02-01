# import all resolvers
from .dns import DNS
from .rdap import RDAP
from .tls import TLS
from .icmp import ICMP
from .ports import PortScan

from .geo.geoip2 import Geo as GeoIP2
from .geo.universal_api import Geo as GeoAPI

from .rep.nerd import NERD

# import other stuff for main resolver
from exceptions import *
from datatypes import DomainData, empty_ip_data
from mongo import MongoWrapper
from datetime import datetime

def resolve_domain(domain: DomainData, mongo: MongoWrapper, mode: str = 'basic', retry_evaluated = False):
  """Resolve domain basic info and store results in db"""
  name = domain['domain_name']
  # set up resolvers
  rdap = RDAP()

  if mode == 'basic':
    # resolve DNS if needed
    if retry_evaluated or domain['remarks']['dns_evaluated_on'] is None:
      dns = DNS()
      try:
        domain['dns'], ips = dns.query(name)
        domain['remarks']['dns_evaluated_on'] = datetime.now()
        domain['remarks']['dns_had_no_ips'] = ips is None
        if ips is not None:
          if domain['ip_data'] is None:
            domain['ip_data'] = []
          for ip in ips:
            if not any(ip_data['ip'] == ip for ip_data in domain['ip_data']):
              domain['ip_data'].append(empty_ip_data(ip))
      except ResolutionImpossible:
        domain['dns'] = None
        domain['remarks']['dns_evaluated_on'] = datetime.now()
        domain['remarks']['dns_had_no_ips'] = False
      except ResolutionNeedsRetry:
        domain['remarks']['dns_evaluated_on'] = None

    # resolve RDAP if needed
    if retry_evaluated or domain['remarks']['rdap_evaluated_on'] is None:
      try:
        domain['rdap'] = rdap.domain(name)
        domain['remarks']['rdap_evaluated_on'] = datetime.now()
      except ResolutionImpossible:
        domain['rdap'] = None
        domain['remarks']['rdap_evaluated_on'] = datetime.now()
      except ResolutionNeedsRetry:
        domain['remarks']['rdap_evaluated_on'] = None

    # resolve TLS if needed
    if retry_evaluated or domain['remarks']['tls_evaluated_on'] is None:
      tls = TLS()
      try:
        domain['tls'] = tls.resolve(name)
      except ResolutionImpossible:
        domain['tls'] = None
      except ResolutionNeedsRetry:
        # immediately retry for timeouts, last chance
        try:
          domain['tls'] = tls.resolve(name, timeout=2)
        except: #anything
          domain['tls'] = None
      finally:
        domain['remarks']['tls_evaluated_on'] = datetime.now()

    # resolve IP RDAP and alive status if needed
    if domain['ip_data'] is not None:
      icmp = ICMP()
      for ip_data in domain['ip_data']:
        # resolve RDAP
        if ip_data['rdap'] is None:
          try:
            ip_data['rdap'] = rdap.ip(ip_data['ip'])
            ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
          except ResolutionImpossible:
            ip_data['rdap'] = None
            ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
          except ResolutionNeedsRetry:
            ip_data['remarks']['rdap_evaluated_on'] = None
        # resolve alive status
        if retry_evaluated or ip_data['remarks']['icmp_evaluated_on'] is None:
          try:
            ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = icmp.ping(ip_data['ip'])
            ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
          except ResolutionImpossible:
            ip_data['remarks']['is_alive'] = False
            ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
          except ResolutionNeedsRetry:
            ip_data['remarks']['icmp_evaluated_on'] = None

    # mark evaluated time
    domain['evaluated_on'] = datetime.now()

  elif mode == 'geo':
    if domain['ip_data'] is not None:
      geo = GeoIP2()
      for ip_data in domain['ip_data']:
        if retry_evaluated or ip_data['remarks']['geo_evaluated_on'] is None:
          try:
            ip_data['geo'] = geo.single(ip_data['ip'])
            ip_data['remarks']['geo_evaluated_on'] = datetime.now()
          except ResolutionImpossible:
            ip_data['geo'] = None
            ip_data['remarks']['geo_evaluated_on'] = datetime.now()
          except ResolutionNeedsRetry:
            ip_data['remarks']['geo_evaluated_on'] = None

  elif mode == 'rep':
    if domain['ip_data'] is not None:
      nerd = NERD(respect_bucket=True) # respect bucket will not help in parallel mode!!
      for ip_data in domain['ip_data']:
        if retry_evaluated or ip_data['remarks']['rep_evaluated_on'] is None:
          if ip_data['rep'] is None:
            ip_data['rep'] = {}
          try:
            ip_data['rep']['nerd'] = nerd.resolve(ip_data['ip'])
            ip_data['remarks']['rep_evaluated_on'] = datetime.now()
          except ResolutionImpossible:
            ip_data['rep']['nerd'] = None
            ip_data['remarks']['rep_evaluated_on'] = datetime.now()
          except ResolutionNeedsRetry:
            ip_data['remarks']['rep_evaluated_on'] = None

  elif mode == 'ports':
    if domain['ip_data'] is not None:
      scanner = PortScan()
      for ip_data in domain['ip_data']:
        if retry_evaluated or ip_data['remarks']['ports_scanned_on'] is None:
          ip_data['ports'] = scanner.scan(ip_data['ip']) #TODO add option to specify ports
          ip_data['remarks']['ports_scanned_on'] = datetime.now()

  # store results
  mongo.store(domain)