from os import getenv
from dotenv import load_dotenv
load_dotenv()

class Config:
  TIMEOUT = 10
  DNS_SERVERS = ['1.1.1.1', '1.0.0.1']
  # MongoDB
  MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
  MONGO_DB = 'drdb'
  MONGO_BATCH_SIZE = 1000
  #
  UA_STRING = 'User-Agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36'