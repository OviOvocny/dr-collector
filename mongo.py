"""Mongo wrapper that handles dataset storage"""
__author__ = "Adam Horák"

import pymongo
import atexit
from typing import List
from config import Config
from datatypes import DomainData, GeoData
from logger import logger

class MongoWrapper:
  batch_queue = []

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
    return self._collection.bulk_write(updates)

  def _upsert_one(self, data: dict, key: str = 'domain_name'):
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
      self._flush(key='domain_name')

  def bulk_store(self, data: List[DomainData]):
    """Bulk store data, no batch queue, no auto collection switching (make sure to switch_collection() first if you need to)"""
    self._upsert(data, key='domain_name')

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

  def get_unresolved(self):
    # find records where at least one of the optional fields in DomainData is None
    return [d for d in self._collection.find({'$or': [{'rdap': None}, {'ip_data': None}, {'tls': None}, {'dns': None}]})]

  def get_resolved(self):
    # find records where all of the optional fields in DomainData are not None
    return [d for d in self._collection.find({'$and': [{'rdap': {'$ne': None}}, {'ip_data': {'$ne': None}}, {'tls': {'$ne': None}}, {'dns': {'$ne': None}}]})]

  def get_names_with_missing(self, fields: List[str]):
    # find names for which all of the specified fields are None
    return [d['domain_name'] for d in self._collection.find({'$and': [{f: None} for f in fields]}, {'domain_name': 1})]