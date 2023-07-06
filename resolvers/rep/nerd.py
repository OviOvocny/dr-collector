"""CESNET NERD resolver for the collector"""
__author__ = "Adam Horák"

import time

import requests

import timing
from config import Config
from exceptions import *
from logger import logger


class NERD:
    def __init__(self, respect_bucket=False):
        self._name = "NERD"
        self._url = Config.NERD_URL
        self._timeout = Config.TIMEOUT
        self._session = requests.Session()
        self._bucket_enabled = respect_bucket
        self._bucket = 200
        # add auth headers
        if Config.NERD_TOKEN:
            self._session.headers["Authorization"] = Config.NERD_TOKEN
        else:
            logger.error("No NERD token provided")
            raise ResolutionImpossible

    def __del__(self):
        self._session.close()

    @timing.time_exec
    def resolve(self, ip):
        # bucket handling is DUMB for now and doesn't take into account the time it takes to resolve
        # this also means WAIT before launching again as the bucket counter is reset on each launch (duh)
        if self._bucket_enabled and self._bucket < 2:  # leave one to be safe
            logger.debug("NERD bucket is empty, waiting for refill")
            time.sleep(1)
            self._bucket += 200
        try:
            r = self._session.get(f"{self._url}/{ip}/full", timeout=self._timeout)
            if self._bucket_enabled:
                self._bucket -= 1
            if r.status_code == 401:
                logger.error(f"NERD token is invalid")
                raise ResolutionNeedsRetry
            body = r.json()
            if r.status_code == 404:
                logger.info(f"NERD could not find {ip}")
                raise ResolutionImpossible
            elif r.status_code == 429:
                logger.error(f"NERD rate limit exceeded: {body['error']}")
                raise ResolutionNeedsRetry
            elif r.status_code >= 500:
                logger.error(f"NERD server error: {body['error']}")
                raise ResolutionNeedsRetry
            elif r.status_code != 200:
                logger.error(f"NERD returned status code {r.status_code}: {body['error']}")
                raise ResolutionImpossible
            return body
        except ValueError as e:
            logger.error(f"NERD response parsing failed: {e}")
            raise ResolutionImpossible
