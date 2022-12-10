from dotenv import load_dotenv
load_dotenv()
from pprint import pprint

from resolvers.ssl import SSL

ssl = SSL()
pprint(ssl.resolve('google.com'))