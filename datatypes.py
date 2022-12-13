"""Nested typed dicts defining the shape of the data the collector creates"""
__author__ = "Adam Horák"


from ipaddress import IPv4Network, IPv6Network
from typing import Union, List, Dict, TypedDict, Optional
from datetime import datetime, timedelta

# DNS
class DNSData(TypedDict):
  """DNS data structure"""
  A: list[str]
  AAAA: list[str]
  CNAME: list[str]
  MX: list[str]
  NS: list[str]
  SOA: list[str]
  TXT: list[str]

# Geo
class GeoData(TypedDict):
  """Geolocation data structure"""
  status: Optional[str]
  message: Optional[str]
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
class RDAPEntity(TypedDict):
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

class RDAPIPData(RDAPBaseData):
  """RDAP IP data structure"""
  country: str
  ip_version: int
  assignment_type: str
  network: Union[IPv4Network, IPv6Network]

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
  valid_len: Optional[timedelta]
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

# DB data record
class IPData(TypedDict):
  """Single IP data structure used in the domain structure"""
  rdap: Optional[RDAPIPData]
  geo: Optional[GeoData]
  rep: Optional[Dict[str, Dict]] # reputation data, entries will have arbitrary shape

class DomainData(TypedDict):
  """Single domain main data structure (goes into DB)"""
  domain_name: str
  label: str # blacklisted/benign as originally sourced, also mongo collection name
  sourced_on: datetime # when the domain was first added
  evaluated_on: Optional[datetime] # when the domain was last evaluated
  # data
  dns: Optional[DNSData]
  rdap: Optional[RDAPDomainData]
  tls: Optional[TLSData]
  ip_data: Optional[Dict[str, IPData]]