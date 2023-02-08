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
from datatypes import DomainData, empty_ip_data, empty_domain_data
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




def try_domain(domain: str, scan_ports = False) -> DomainData:
  """Resolve domain without storing results."""
  # init all resolvers
  dns = DNS()
  rdap = RDAP()
  tls = TLS()
  icmp = ICMP()
  geo = GeoIP2()
  nerd = NERD()
  scanner = PortScan()
  # init domain data
  domain_data = empty_domain_data({
    'name': domain,
    'source': 'try_domain',
    'category': 'try_domain'
  }, 'test')
  # resolve DNS
  try:
    dns_data, ips = dns.query(domain)
    domain_data['dns'] = dns_data
    domain_data['remarks']['dns_evaluated_on'] = datetime.now()
    if ips is None:
      domain_data['remarks']['dns_had_no_ips'] = True
    else:
      domain_data['remarks']['dns_had_no_ips'] = False
      domain_data['ip_data'] = []
      for ip in ips:
        domain_data['ip_data'].append(empty_ip_data(ip))
  except ResolutionImpossible:
    domain_data['dns'] = None
    domain_data['remarks']['dns_evaluated_on'] = datetime.now()
    domain_data['remarks']['dns_had_no_ips'] = False
  except ResolutionNeedsRetry:
    domain_data['remarks']['dns_evaluated_on'] = None
    domain_data['remarks']['dns_had_no_ips'] = False
  # resolve RDAP
  try:
    domain_data['rdap'] = rdap.domain(domain)
    domain_data['remarks']['rdap_evaluated_on'] = datetime.now()
  except ResolutionImpossible:
    domain_data['rdap'] = None
    domain_data['remarks']['rdap_evaluated_on'] = datetime.now()
  except ResolutionNeedsRetry:
    domain_data['remarks']['rdap_evaluated_on'] = None
  # resolve TLS
  try:
    domain_data['tls'] = tls.resolve(domain)
    domain_data['remarks']['tls_evaluated_on'] = datetime.now()
  except ResolutionImpossible:
    domain_data['tls'] = None
    domain_data['remarks']['tls_evaluated_on'] = datetime.now()
  except ResolutionNeedsRetry:
    domain_data['remarks']['tls_evaluated_on'] = None
  # IPs
  if domain_data['ip_data'] is not None:
    for ip_data in domain_data['ip_data']:
      ip_data['rep'] = {}
      # try ICMP ping
      try:
        ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = icmp.ping(ip_data['ip'])
        ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
      except ResolutionImpossible:
        ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = False, None
        ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
      except ResolutionNeedsRetry:
        ip_data['remarks']['icmp_evaluated_on'] = None
      # resolve geo
      try:
        ip_data['geo'] = geo.single(ip_data['ip'])
        ip_data['remarks']['geo_evaluated_on'] = datetime.now()
      except ResolutionImpossible:
        ip_data['geo'] = None
        ip_data['remarks']['geo_evaluated_on'] = datetime.now()
      except ResolutionNeedsRetry:
        ip_data['remarks']['geo_evaluated_on'] = None      
      # resolve reputation
      try:
        ip_data['rep']['nerd'] = nerd.resolve(ip_data['ip'])
        ip_data['remarks']['rep_evaluated_on'] = datetime.now()
      except ResolutionImpossible:
        ip_data['rep']['nerd'] = None
        ip_data['remarks']['rep_evaluated_on'] = datetime.now()
      except ResolutionNeedsRetry:
        ip_data['remarks']['rep_evaluated_on'] = None
      # resolve ports
      if scan_ports:
        try:
          ip_data['ports'] = scanner.scan(ip_data['ip']) #TODO add option to specify ports
          ip_data['remarks']['ports_scanned_on'] = datetime.now()
        except ResolutionImpossible:
          ip_data['ports'] = []
          ip_data['remarks']['ports_scanned_on'] = datetime.now()
        except ResolutionNeedsRetry:
          ip_data['remarks']['ports_scanned_on'] = None
      else:
        ip_data['ports'] = []
        ip_data['remarks']['ports_scanned_on'] = None
  # return results
  return domain_data
