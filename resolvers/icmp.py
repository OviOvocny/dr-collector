"""Self-contained ping resolver for the pong collector to see if host is alive"""
__author__ = "Adam Horák"

import sys
from typing import Tuple, List, Dict
from icmplib import ping, multiping
from icmplib.exceptions import NameLookupError, SocketAddressError, SocketPermissionError

import dr_collector.timing as timing
from dr_collector.logger import logger_resolvers as logger
from dr_collector.config import Config
from dr_collector.exceptions import *


class ICMP:
    def __init__(self, count=1, interval=1, timeout=Config.TIMEOUT):
        self._count = count
        self._interval = interval
        self._timeout = timeout

    @timing.time_exec
    def ping(self, address: str) -> Tuple[bool, float]:
        """Ping a single host and return (is_alive, avg_rtt)"""
        try:
            result = ping(address, count=self._count, interval=self._interval, timeout=self._timeout)
            return result.is_alive, result.avg_rtt
        except SocketPermissionError:
            print("ICMP: No permission to create raw socket!", file=sys.stderr)
            raise ResolutionNeedsRetry
        except (NameLookupError, SocketAddressError) as e:
            logger.error("Error during ping: " + str(e))
            raise ResolutionNeedsRetry
        except BaseException as e:
            logger.error("Error during ping", exc_info=e)
            raise ResolutionImpossible

    @timing.time_exec
    def ping_list(self, addresses: List[str]) -> Dict[str, Tuple[bool, float]]:
        """Ping a list of hosts and return a {address: (is_alive, avg_rtt)} dict"""
        try:
            results = multiping(addresses, count=self._count, interval=self._interval, timeout=self._timeout)
            return {result.address: (result.is_alive, result.avg_rtt) for result in results}
        except SocketPermissionError:
            print("ICMP: No permission to create raw socket!", file=sys.stderr)
            raise ResolutionNeedsRetry
        except (NameLookupError, SocketAddressError) as e:
            logger.error("Error during ping: " + str(e))
            raise ResolutionNeedsRetry
        except BaseException as e:
            logger.error("Error during ping", exc_info=e)
            raise ResolutionImpossible
