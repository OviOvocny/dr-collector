"""Self-contained port scan resolver for the collector to see what is open"""
__author__ = "Adam Horák"

from typing import List, Dict
from logger import logger
from config import Config
from exceptions import *
import socket

class PortScan:
  def __init__(self, default_ports = [80, 443, 20, 21, 22, 25, 53, 110, 143], timeout = Config.TIMEOUT):
    self._ports = default_ports
    self._timeout = timeout

  def _is_open(self, address: str, port: int) -> bool:
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(self._timeout)
      sock.connect((address, port))
      sock.close()
      return True
    except:
      return False

  def scan(self, address: str, ports: List[int] = []) -> List[int]:
    """Scan a list of single host's ports and return a list of those that are open"""
    port_list = ports if len(ports) > 0 else self._ports
    return [port for port in port_list if self._is_open(address, port)]