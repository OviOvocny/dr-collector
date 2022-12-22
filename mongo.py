"""Mongo wrapper that handles dataset storage"""
__author__ = "Adam Horák"

import sys
import pymongo
import atexit
import concurrent.futures
from math import ceil
from typing import List
from config import Config
from datatypes import DomainData, GeoData
from logger import logger

def chunks(l: List, n: int):
  """Yield successive equal about-n-sized chunks from l."""
  chunk_count = len(l) // n
  chunk_size = ceil(len(l) / chunk_count)
  for i in range(0, len(l), chunk_size):
    yield l[i:i + chunk_size]

class MongoWrapper:
  batch_queue = []

  @staticmethod
  def test_connection():
    try:
      client = pymongo.MongoClient(Config.MONGO_URI)
      client.server_info()
    except:
      logger.error("DB: Connection to MongoDB failed, check your connection settings")
      print("Connection to MongoDB failed, check your connection settings. Exiting...")
      sys.exit(1)

  def __init__(self, collection: str, batch_size: int = Config.MONGO_BATCH_SIZE):
    self._client = pymongo.MongoClient(Config.MONGO_URI)
    self._db = self._client[Config.MONGO_DB]
    self._collection = self._db[collection]
    self.batch_size = batch_size
    atexit.register(self._cleanup)

  def _cleanup(self):
    if len(self.batch_queue) < self.batch_size and len(self.batch_queue) > 0:
      logger.debug("DB: Flushed remaining " + str(len(self.batch_queue)) + " items before exit")
    self._flush('domain_name')
    self._client.close()

  def _insert(self, data: List):
    return self._collection.insert_many(data)

  def _upsert(self, data: List, key: str):
    updates = [pymongo.UpdateOne({key: d[key]}, {'$set': d}, upsert=True) for d in data]
    return self._collection.bulk_write(updates, ordered=False)

  def _upsert_one(self, data: dict, key: str):
    return self._collection.update_one({key: data[key]}, {'$set': data}, upsert=True)

  def _flush(self, key: str):
    if self.batch_queue:
      self._upsert(self.batch_queue, key)
      self.batch_queue.clear()

  def switch_collection(self, collection: str):
    logger.debug("DB: Switching to collection " + collection)
    self._collection = self._db[collection]

# storing

  def store(self, data: DomainData):
    """Abstracts away batch queue and collection switching, use this just as you would an single insert method"""
    # flush current batch queue if collection name changed, then switch
    if self._collection.name != data['label']:
      logger.debug("DB: Collection name changed, flushing batch queue and switching to " + data['label'])
      self._flush(key='domain_name')
      self.switch_collection(data['label'])
    # add to batch queue
    self.batch_queue.append(data)
    # flush if batch queue is full
    if len(self.batch_queue) >= self.batch_size:
      logger.debug("DB: Batch queue full, flushing " + str(len(self.batch_queue)) + " items")
      self._flush(key='domain_name')

  def bulk_store(self, data: List[DomainData]):
    """Bulk store data, no batch queue, no auto collection switching (make sure to switch_collection() first if you need to)"""
    self._upsert(data, key='domain_name')

  def parallel_store(self, data: List[DomainData]):
    """Store data in parallel, no batch queue, no auto collection switching (make sure to switch_collection() first if you need to)"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
      print(f'Preparing {len(data)} items...', end='\r')
      futures = [executor.submit(self._upsert, chunk, 'domain_name') for chunk in chunks(data, Config.MONGO_BATCH_SIZE)]
      print(f'Sending {len(data)} items...  ', end='\r')
      complete = 0
      stored = 0
      for future in concurrent.futures.as_completed(futures):
        complete += 1
        stored += future.result().upserted_count
        print(str(stored) + ' items [' + '#' * complete + ' ' * (len(futures) - complete) + ']', end='\r')
      sys.stdout.write("\033[K")
      print(f'Stored {stored} of {len(data)} items in {len(futures)} writes')
    return stored, len(futures)

  def set_by_path(self, domain_name: str, path: str, data):
    return self._collection.update_one({'domain_name': domain_name}, {'$set': {path: data}})

  def set_geo(self, domain_name: str, ip: str, data: GeoData):
    return self._collection.update_one({'domain_name': domain_name}, {'$set': {f'ip_data.{ip}.geo': data}})

# retrieving

  def get_all(self, names_only = False):
    if names_only:
      return [d['domain_name'] for d in self._collection.find({}, {'domain_name': 1})]
    else:
      return [d for d in self._collection.find({})]

  def get_unresolved(self, retry_evaluated = False, limit: int = 0):
    if retry_evaluated:
      # find records with empty data fields
      return [d for d in self._collection.find({'$or': [{'rdap': None}, {'ip_data': None}, {'ip_data': {'$elemMatch': {'rdap': None}}}, {'tls': None}, {'dns': None}]}, limit=limit)]
    else:
      # find records with missing evaluation dates in remarks
      return [d for d in self._collection.find({'$or': [{'remarks.rdap_evaluated_on': None}, {'ip_data': {'$elemMatch': {'remarks.rdap_evaluated_on': None}}}, {'remarks.tls_evaluated_on': None}, {'remarks.dns_evaluated_on': None}]}, limit=limit)]

  def get_unresolved_geo(self, retry_evaluated = False, limit: int = 0):
    # find records where at least one of the dicts in ip_data has no geo_evaluated key, limit to limit
    if retry_evaluated:
      return [d for d in self._collection.find({'ip_data': {'$elemMatch': {'geo': None}}}, limit=limit)]
    return [d for d in self._collection.find({'ip_data': {'$elemMatch': {'remarks.geo_evaluated_on': None}}}, limit=limit)]

  def get_resolved(self):
    # find records where all of the optional fields in DomainData are not None
    return [d for d in self._collection.find({'$and': [{'rdap': {'$ne': None}}, {'ip_data': {'$ne': None}}, {'tls': {'$ne': None}}, {'dns': {'$ne': None}}]})]

  def get_names_with_missing(self, fields: List[str]):
    # find names for which all of the specified fields are None
    return [d['domain_name'] for d in self._collection.find({'$and': [{f: None} for f in fields]}, {'domain_name': 1})]