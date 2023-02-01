"""Self-contained ping resolver for the pong collector to see if host is alive"""
__author__ = "Adam Horák"

from typing import Tuple, List, Dict
from icmplib import ping, multiping, Host
from icmplib.exceptions import NameLookupError, SocketPermissionError, SocketAddressError
from logger import logger
from config import Config
from exceptions import *

class ICMP:
  def __init__(self, count = 4, interval = 1, timeout = Config.TIMEOUT):
    self._count = count
    self._interval = interval
    self._timeout = timeout

  def ping(self, address: str) -> Tuple[bool, float]:
    """Ping a single host and return (is_alive, avg_rtt)"""
    try:
      result = ping(address, count=self._count, interval=self._interval, timeout=self._timeout)
      return (result.is_alive, result.avg_rtt)
    except (NameLookupError, SocketPermissionError, SocketAddressError) as e:
      logger.error("Error during ping: " + str(e))
      raise ResolutionNeedsRetry
    except:
      raise ResolutionImpossible

  def ping_list(self, addresses: List[str]) -> Dict[str, Tuple[bool, float]]:
    """Ping a list of hosts and return a {address: (is_alive, avg_rtt)} dict"""
    try:
      results = multiping(addresses, count=self._count, interval=self._interval, timeout=self._timeout)
      return {result.address: (result.is_alive, result.avg_rtt) for result in results}
    except (NameLookupError, SocketPermissionError, SocketAddressError) as e:
      logger.error("Error during ping: " + str(e))
      raise ResolutionNeedsRetry
    except:
      raise ResolutionImpossible