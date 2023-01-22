"""Nested typed dicts defining the shape of the data the collector creates"""
__author__ = "Adam Horák"


from typing import Union, List, Dict, TypedDict, Optional
from datetime import datetime

class Domain(TypedDict):
  """Domain data structure for loaders"""
  name: str
  source: str
  category: str

####

# DNS
class DNSData(TypedDict):
  """DNS data structure"""
  A: Optional[List[str]]
  AAAA: Optional[List[str]]
  CNAME: Optional[List[str]]
  MX: Optional[List[str]]
  NS: Optional[List[str]]
  SOA: Optional[List[str]]
  TXT: Optional[List[str]]

# Geo
class GeoData(TypedDict):
  """Geolocation data structure"""
  country: Optional[str]
  country_code: Optional[str]
  region: Optional[str]
  region_code: Optional[str]
  city: Optional[str]
  postal_code: Optional[str]
  latitude: Optional[float]
  longitude: Optional[float]
  timezone: Optional[str]
  asn: Optional[int]
  as_org: Optional[str]
  isp: Optional[str]
  org: Optional[str]

#RDAP
class RDAPEntity(TypedDict, total=False):
  """RDAP entity structure (used in the entities list, not a specific query result)"""
  email: str
  handle: str
  name: str
  rir: str
  type: str
  url: str
  whois_server: str

class RDAPBaseData(TypedDict):
  """RDAP result shared data structure"""
  handle: str
  parent_handle: str
  name: str
  whois_server: str
  type: str
  terms_of_service_url: str
  copyright_notice: str
  description: List[str]
  last_changed_date: Optional[datetime]
  registration_date: Optional[datetime]
  expiration_date: Optional[datetime]
  rir: str
  url: str
  entities: Dict[str, List[RDAPEntity]]

class RDAPDomainData(RDAPBaseData):
  """RDAP domain data structure"""
  nameservers: List[str]
  status: List[str]

class IPNetwork(TypedDict):
  """IP network structure"""
  prefix_length: int
  network_address: str
  netmask: str
  broadcast_address: str
  hostmask: str

class RDAPIPData(RDAPBaseData):
  """RDAP IP data structure"""
  country: str
  ip_version: int
  assignment_type: str
  network: IPNetwork

class RDAPASNData(RDAPBaseData):
  """RDAP ASN data structure"""
  asn_range: List[int]

class RDAPEntityData(RDAPBaseData):
  """RDAP entity data structure (extends RDAPBaseData, this is used when you query the RDAP service for an entity explicitly)"""
  email: str

#TLS
class CertificateExtension(TypedDict):
  """X.509 Certificate extension structure"""
  critical: bool
  name: str
  value: str

class Certificate(TypedDict):
  """Certificate structure"""
  common_name: Optional[str]
  country: Optional[str]
  is_root: bool
  organization: Optional[str]
  valid_len: Optional[int]
  validity_end: Optional[datetime]
  validity_start: Optional[datetime]
  extension_count: int
  extensions: List[CertificateExtension]

class TLSData(TypedDict):
  """TLS data structure for one domain"""
  protocol: str
  cipher: str
  count: int
  certificates: List[Certificate]

class IPRemarks(TypedDict):
  """Remarks for finding unfinished IPs"""
  # dates of last FINISHED evaluation (either OK or not worth retrying)
  rdap_evaluated_on: Optional[datetime]
  geo_evaluated_on: Optional[datetime]
  rep_evaluated_on: Optional[datetime]

# DB data record
class IPData(TypedDict):
  """Single IP data structure used in the domain structure"""
  ip: str
  remarks: IPRemarks
  rdap: Optional[RDAPIPData]
  geo: Optional[GeoData]
  rep: Optional[Dict[str, Optional[Dict]]] # reputation data, entries will have arbitrary shape

class DomainRemarks(TypedDict):
  """Remarks for finding unfinished domains"""
  # dates of last FINISHED evaluation (either OK or not worth retrying)
  dns_evaluated_on: Optional[datetime]
  rdap_evaluated_on: Optional[datetime]
  tls_evaluated_on: Optional[datetime]
  # special flag for domains that had no IPs in DNS
  dns_had_no_ips: bool

class DomainData(TypedDict):
  """Single domain main data structure (goes into DB)"""
  domain_name: str
  label: str # blacklisted/benign as originally sourced, also mongo collection name
  source: str # source of the domain (uri of the list, etc.)
  category: str # category of the domain (malware, phishing, etc.)
  sourced_on: datetime # when the domain was first added
  evaluated_on: Optional[datetime] # when the domain was last evaluated
  remarks: DomainRemarks # info about resolution - dates, failures, etc. (for finding unfinished domains)
  # data
  dns: Optional[DNSData]
  rdap: Optional[RDAPDomainData]
  tls: Optional[TLSData]
  ip_data: Optional[List[IPData]]

def empty_domain_data(domain: Domain, label: str) -> DomainData:
  """Returns an empty DomainData structure"""
  return {
    'domain_name': domain['name'],
    'label': label,
    'source': domain['source'],
    'category': domain['category'],
    'sourced_on': datetime.now(),
    'evaluated_on': None,
    'remarks': {
      'dns_evaluated_on': None,
      'rdap_evaluated_on': None,
      'tls_evaluated_on': None,
      'dns_had_no_ips': False
    },
    'dns': None,
    'rdap': None,
    'tls': None,
    'ip_data': None
  }

def empty_ip_data(ip: str) -> IPData:
  """Returns an empty IPData structure"""
  return {
    'ip': ip,
    'remarks': {
      'rdap_evaluated_on': None,
      'geo_evaluated_on': None,
      'rep_evaluated_on': None
    },
    'rdap': None,
    'geo': None,
    'rep': None
  }