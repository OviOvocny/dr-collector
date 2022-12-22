# import all resolvers
from .dns import DNS
from .rdap import RDAP
from .tls import TLS

from .geo.geoip2 import Geo as GeoIP2
from .geo.universal_api import Geo as GeoAPI

from .rep.nerd import NERD