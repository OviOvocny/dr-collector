from os import getenv
from dotenv import load_dotenv
load_dotenv()

class Config:
  TIMEOUT = 3
  DNS_SERVERS = ['193.17.47.1', '185.43.135.1']
  MAX_WORKERS = None
  # MongoDB
  MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
  MONGO_DB = 'drdb'
  MONGO_BATCH_SIZE = 500
  #
  UA_STRING = 'User-Agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36'
  # NERD
  NERD_URL = 'https://nerd.cesnet.cz/nerd/api/v1/ip/'
  NERD_TOKEN = getenv('DR_NERD_TOKEN')