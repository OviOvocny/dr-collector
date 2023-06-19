"""Mongo wrapper that handles dataset storage"""
__author__ = "Adam Horák"

import sys
import click
import pymongo
import pymongo.errors
from pymongo.cursor import Cursor
import atexit
import concurrent.futures
from math import ceil
from typing import List, Tuple
from config import Config
from datatypes import DomainData, GeoData
from logger import logger


def chunks(source_list: List, n: int):
    """Yield successive equal about-n-sized chunks from source_list."""
    chunk_count = ceil(len(source_list) / n)
    if chunk_count == 0:
        yield source_list
    else:
        chunk_size = ceil(len(source_list) / chunk_count)
        for i in range(0, len(source_list), chunk_size):
            yield source_list[i:i + chunk_size]


class MongoWrapper:
    batch_queue = []

    @staticmethod
    def test_connection():
        try:
            client = pymongo.MongoClient(Config.MONGO_URI)
            client.server_info()
        except BaseException:
            logger.error("DB: Connection to MongoDB failed, check your connection settings")
            print("Connection to MongoDB failed, check your connection settings. Exiting...")
            sys.exit(1)

    def __init__(self, collection: str, batch_size: int = Config.MONGO_BATCH_SIZE):
        self._client = pymongo.MongoClient(Config.MONGO_URI)
        self._db = self._client[Config.MONGO_DB]
        self._collection = self._db[collection]
        self.batch_size = batch_size
        self._closed = False
        atexit.register(self.cleanup)

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        if self._closed:
            return

        if self.batch_size > len(self.batch_queue) > 0:
            logger.debug("DB: Flushed remaining " + str(len(self.batch_queue)) + " items before exit")
        self._flush('domain_name')
        self._client.close()
        self._closed = True

    def _insert(self, data: List):
        return self._collection.insert_many(data)

    def _upsert(self, data: List, key: str, skip_duplicates: bool = False):
        updates = [pymongo.UpdateOne({key: d[key]},
                                     {'$setOnInsert' if skip_duplicates else '$set': d},
                                     upsert=True) for d in data]
        return self._collection.bulk_write(updates, ordered=False)

    def _upsert_one(self, data: dict, key: str):
        return self._collection.update_one({key: data[key]}, {'$set': data}, upsert=True)

    def _flush(self, key: str, skip_duplicates: bool = False):
        if self.batch_queue:
            self._upsert(self.batch_queue, key, skip_duplicates)
            self.batch_queue.clear()

    def switch_collection(self, collection: str):
        logger.debug("DB: Switching to collection " + collection)
        self._collection = self._db[collection]

    def index_by(self, key: str):
        try:
            self._collection.create_index(key, name=f'{key}_index', unique=True)
        except pymongo.errors.OperationFailure:
            pass

    def update_one(self, filter: dict, data: dict):
        return self._collection.update_one(filter, data)

# storing

    def store(self, data: DomainData, skip_duplicates: bool = False):
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
            self._flush(key='domain_name', skip_duplicates=skip_duplicates)

    def bulk_store(self, data: List[DomainData]):
        """Bulk store data, no batch queue, no auto collection switching (make sure to switch_collection() first
        if you need to)"""
        self._upsert(data, key='domain_name')

    def parallel_store(self, data: List[DomainData], skip_duplicates: bool = False):
        """Store data in parallel, no batch queue, no auto collection switching (make sure to switch_collection() first
        if you need to)"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            click.echo(f'Preparing {len(data)} items...')
            futures = [executor.submit(self._upsert, chunk, 'domain_name', skip_duplicates)
                       for chunk in chunks(data, Config.MONGO_BATCH_SIZE)]
            stored = 0
            with click.progressbar(length=len(futures), show_pos=True, show_percent=True, label="Writes") as loading:
                for future in concurrent.futures.as_completed(futures):
                    loading.update(1)
                    stored += future.result().upserted_count
            result = f'Stored {stored} of {len(data)} items in {len(futures)} writes'
            logger.info(result)
            click.echo(result)
        return stored, len(futures)

    def set_by_path(self, domain_name: str, path: str, data):
        return self._collection.update_one({'domain_name': domain_name}, {'$set': {path: data}})

    def set_geo(self, domain_name: str, ip: str, data: GeoData):
        return self._collection.update_one({'domain_name': domain_name}, {'$set': {f'ip_data.{ip}.geo': data}})

# retrieving

    def get_all(self, names_only=False):
        if names_only:
            return [d['domain_name'] for d in self._collection.find({}, {'domain_name': 1})]
        else:
            return [d for d in self._collection.find({})]

    def _find_query(self, query, limit: int = 0) -> Tuple[Cursor[DomainData], int]:
        db_count = self._collection.count_documents(query)
        count = db_count if limit == 0 else min(limit, db_count)
        return self._collection.find(query, limit=limit, batch_size=Config.MONGO_BATCH_SIZE), count

    def get_unresolved(self, retry_evaluated=False, limit: int = 0):
        query = {'$or': [{'remarks.rdap_evaluated_on': None},
                         {'ip_data': {'$elemMatch': {'remarks.rdap_evaluated_on': None}}},
                         {'remarks.tls_evaluated_on': None},
                         {'remarks.dns_evaluated_on': None}]}
        if retry_evaluated:
            query = {
                '$or': [
                    {
                        'rdap': None}, {
                        'ip_data': None}, {
                        'ip_data': {
                            '$elemMatch': {
                                'rdap': None}}}, {
                        'tls': None}, {
                                    'dns': None}]}
        return self._find_query(query, limit)

    def get_unresolved_geo(self, retry_evaluated=False, limit: int = 0):
        query = {'ip_data': {'$elemMatch': {'remarks.geo_evaluated_on': None}}}
        if retry_evaluated:
            query = {'ip_data': {'$elemMatch': {'geo': None}}}
        return self._find_query(query, limit)

    def get_unresolved_rep(self, retry_evaluated=False, limit: int = 0):
        # find records where at least one IP is missing rep data, limit to limit
        reps = ['nerd']
        query = {'ip_data': {'$elemMatch': {'remarks.rep_evaluated_on': None}}}
        if retry_evaluated:
            query = {'$or': [{'ip_data': {'$elemMatch': {f'rep.{service}': None}}} for service in reps]}
        return self._find_query(query, limit)

    def get_unresolved_ports(self, retry_evaluated=False, limit: int = 0):
        query = {'ip_data': {'$elemMatch': {'remarks.ports_scanned_on': None}}}
        if retry_evaluated:
            query = {'ip_data': {'$exists': True}}
        return self._find_query(query, limit)

    def get_resolved(self):
        # find records where all of the optional fields in DomainData are not None
        query = {'evaluated_on': {'$ne': None}}
        return self._find_query(query)

    def get_names_with_missing(self, fields: List[str]):
        # find names for which all of the specified fields are None
        return [d['domain_name'] for d in self._collection.find(
            {'$and': [{f: None} for f in fields]}, {'domain_name': 1})]
