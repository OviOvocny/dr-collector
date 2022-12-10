"""Universal geolocation resolver for the collector, can connect to various APIs"""
__author__ = "Adam Horák"
# FYI: These APIs are heavily rate-limited or paid. RDAP can be used to get country data for IP addresses.

from datatypes import GeoData
from typing import Union, List, Tuple, Callable
import requests
import time

def default_mapper(data: dict) -> GeoData:
  """
  Default mapping function for geolocation data from ip-api.com
  Takes the API response and maps the fields to a GeoData object
  """
  asys: Union[str,None] = data.get("as", None)
  asn = int(asys.split(" ")[0][2:]) if asys else 0
  as_org = asys.split(" ", 1)[1] if asys else ""
  return {
    "status": "success",
    "message": "",
    "country": data.get("country", ""),
    "country_code": data.get("countryCode", ""),
    "region": data.get("regionName", ""),
    "region_code": data.get("region", ""),
    "city": data.get("city", ""),
    "postal_code": data.get("zip", ""),
    "latitude": data.get("lat", 0),
    "longitude": data.get("lon", 0),
    "timezone": data.get("timezone", ""),
    "asn": asn,
    "as_org": as_org,
    "isp": data.get("isp", ""),
    "org": data.get("org", "")
  }

def default_request_constructor(url: str, ips: List[str], ips_per_request = 1) -> Tuple[requests.Request, List[str]]:
  """
  Default request constructor for ip-api.com
  Returns a tuple of a request that the API accepts and a list of remaining IPs
  """
  return requests.Request("POST", url, json=ips[:ips_per_request]), ips[ips_per_request:]

class Geo:
  def __init__(self,
    api_endpoint: str = "http://ip-api.com/batch",
    api_key: Union[str,None] = None,
    fields_mapper: Callable[[dict], GeoData] = default_mapper,
    request_constructor: Callable[[str, List[str], int], Tuple[requests.Request, List[str]]] = default_request_constructor
  ):
    self._api = api_endpoint
    self._key = api_key
    self._mapper = fields_mapper
    self._constructor = request_constructor
    # api call limits, default to no limits
    self._requests_per_period = float("inf")
    self._cooldown_seconds = 0

  def set_throttling(self, limit: int, period: int):
    """Set API call limits: request number per period in seconds"""
    self._requests_per_period = limit
    self._cooldown_seconds = period

  def query(self, ips: List[str], ips_per_request = 1) -> List[GeoData]:
    """Query the API for geolocation data for a list of IPs"""
    session = requests.Session()
    requests_sent = 0
    ip_list = ips
    results: List[GeoData] = []
    while len(ip_list) > 0:
      # throttle requests
      if requests_sent >= self._requests_per_period:
        requests_sent = 0
        time.sleep(self._cooldown_seconds)
      # send request for defined amount of IPs and remove them from the list
      req, ip_list = self._constructor(self._api, ip_list, ips_per_request)
      resp = session.send(req.prepare())
      requests_sent += 1
      if resp.status_code == 200:
        data = resp.json()
        if type(data) is list:
          results += [self._mapper(d) for d in data]
        else:
          results.append(self._mapper(data))
    session.close()
    return results

  def single(self, ip: str) -> GeoData:
    """Query the API for geolocation data for a single IP"""
    return self.query([ip])[0]