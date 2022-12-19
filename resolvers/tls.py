"""TLS resolver with X.509 extension reader"""
__author__      = "Adam Horák"

import socket
import OpenSSL.SSL
from OpenSSL.crypto import X509
import datetime

from config import Config
from logger import logger
from typing import List
from datatypes import TLSData, Certificate, CertificateExtension

class TLS:
  def __init__(self, timeout = Config.TIMEOUT):
    self.timeout = timeout

  #
  def _download(self, host: str, port: int = 443):
    """Download TLS certificate chain from host:port"""
    result = {}
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    ctx.set_timeout(self.timeout)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(self.timeout)

    try:
      sock.connect((host, port))
      get = str.encode(f"GET / HTTP/1.1\n{Config.UA_STRING}\n\n")
      sock.send(get)
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock = OpenSSL.SSL.Connection(context=ctx, socket=sock)
      sock.settimeout(self.timeout)
      sock.connect((host, 443))
      sock.setblocking(1)
      sock.set_connect_state()
      sock.set_tlsext_host_name(str.encode(host))
      sock.do_handshake()
      result["cipher_name"] = sock.get_cipher_name()
      chain = sock.get_verified_chain()
      result["chain_len"] = len(chain) if chain else 0
      result["protocol"] = sock.get_protocol_version_name()
      result["cert_chain"] = chain
    except socket.gaierror as e:
      logger.error("Cant resolve domain name or connection error")
      return None
    except socket.timeout as e:
      logger.error("socket intimeout")
      return None
    except OpenSSL.SSL.Error as e:
      logger.error("cannot find any root certificates")
      return None
    except ConnectionRefusedError as e:
      logger.error("connection refused")
      return None
    except OSError as e:
      logger.error("built-in exception in Python")
      return None

    try:
      sock.shutdown()
      sock.close()
    except:
      logger.error("Fatal error during socket closing")
      return None

    return result

  #
  def _parse_certificate(self, cert: X509, is_root = False):
    """Parse certificate and return Certificate object"""
    # Parse validity
    valid_from_raw = cert.get_notBefore()
    valid_to_raw = cert.get_notAfter()
    if valid_from_raw is None or valid_to_raw is None:
      logger.error("Certificate validity is None")
      valid_from = None
      valid_to = None
      validity_len = None
    else:
      valid_to = datetime.datetime.strptime(valid_to_raw.decode("utf-8")[:-1], "%Y%m%d%H%M%S")
      valid_from = datetime.datetime.strptime(valid_from_raw.decode("utf-8")[:-1], "%Y%m%d%H%M%S")
      validity_len = valid_to - valid_from
    
    # Parse issuer info
    attributes = str(cert.get_issuer()).split('/')
    common_name = None
    organization = None
    country = None
    for attr in attributes:
      key, val = attr.split('=')
      if key == 'CN':
        common_name = val
      elif key == 'O':
        organization = val
      elif key == 'C':
        country = val

    # Parse extensions
    extensions: List[CertificateExtension] = []
    for i in range(cert.get_extension_count()):
      ext = cert.get_extension(i)
      extensions.append({
        "critical": ext.get_critical(),
        "name": ext.get_short_name().decode("utf-8"),
        "value": ext.get_data().decode("asn1")
      })
    
    return Certificate(
      common_name = common_name,
      organization = organization,
      country = country,
      validity_start = valid_from,
      validity_end = valid_to,
      valid_len = validity_len,
      extensions = extensions,
      extension_count=len(extensions),
      is_root = is_root
    )

  #
  def _parse_chain(self, chain: List[X509]):
    """Parse certificate chain and return list of Certificate objects"""
    result: List[Certificate] = []
    for i, cert in enumerate(chain):
      result.append(self._parse_certificate(cert, i == len(chain) - 1))
    return result

  #
  def resolve(self, host: str, port: int = 443):
    """Resolve TLS data from host:port"""
    data = self._download(host, port)
    return None if data is None else TLSData(
        cipher = data["cipher_name"],
        count = data["chain_len"],
        protocol = data["protocol"],
        certificates = self._parse_chain(data["cert_chain"])
      )