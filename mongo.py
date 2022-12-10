"""Mongo wrapper that handles dataset storage"""
__author__ = "Adam Horák"

import pymongo
import atexit
from typing import List
from config import Config
from datatypes import DomainData, GeoData

class MongoWrapper:
  batch_queue = []

  def __init__(self, collection: str, batch_size: int = Config.MONGO_BATCH_SIZE):
    self._client = pymongo.MongoClient(Config.MONGO_URI)
    self._db = self._client[Config.MONGO_DB]
    self._collection = self._db[collection]
    self.batch_size = batch_size
    atexit.register(self._cleanup)

  def _cleanup(self):
    self._flush('domain_name')
    self._client.close()

  def _insert(self, data: List):
    return self._collection.insert_many(data)

  def _upsert(self, data: List, key: str):
    updates = [pymongo.UpdateOne({key: d[key]}, {'$set': d}, upsert=True) for d in data]
    return self._collection.bulk_write(updates)

  def _flush(self, key: str):
    if self.batch_queue:
      self._upsert(self.batch_queue, key)
      self.batch_queue.clear()

  def switch_collection(self, collection: str):
    self._collection = self._db[collection]

  def store(self, data: DomainData):
    """Abstracts away batch queue and collection switching, use this just as you would an single insert method"""
    # flush current batch queue if collection name changed, then switch
    if self._collection.name != data['label']:
      self._flush(key='domain_name')
      self.switch_collection(data['label'])
    # add to batch queue
    self.batch_queue.append(data)
    # flush if batch queue is full
    if len(self.batch_queue) >= self.batch_size:
      self._flush(key='domain_name')

  def set_geo(self, domain_name: str, ip: str, data: GeoData):
    return self._collection.update_one({'domain_name': domain_name}, {'$set': {f'ip_data.{ip}.geo': data}})

  def get_all(self, names_only = False):
    if names_only:
      return [d['domain_name'] for d in self._collection.find({}, {'domain_name': 1})]
    else:
      return [d for d in self._collection.find({})]