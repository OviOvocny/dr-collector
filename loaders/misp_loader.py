"""
MISP domain name loader - reads a MISP feed and loads domain names from it
"""
__author__ = "Jan Polišenský, Adam Horák"

from typing import List
from logger import logger
from datatypes import Domain
from config import Config
from pymisp import ExpandedPyMISP  # type: ignore - linter is confused

import re
from loaders.utils import LoaderUtils as U


class MISPLoader:
    """Local file data loader for the collector"""
    valid_sources = ("plain", "octet-stream", "html", "csv")

    def __init__(self, feed_name: str):
        if Config.MISP_URL is None or Config.MISP_KEY is None:
            print("Missing MISP configuration, please check config.py")
            exit(3)
        self.source = feed_name
        self.feed_id, self.category = Config.MISP_FEEDS[feed_name]
        self.misp = ExpandedPyMISP(Config.MISP_URL, Config.MISP_KEY, Config.MISP_VERIFYCERT)

    def load(self):
        """A generator that just yields the domains found (generator is used for consistency with other loaders)"""
        domain_names: List[Domain] = []
        event = self.misp.get_event(self.feed_id, pythonify=True)
        for i in event:
            if i == 'Attribute':
                for j in event[i]:
                    domain = re.search(U.hostname_regex, j.value)
                    if domain:
                        dom_name = domain.group(0)  # type: str
                        domain_names.append({
                            'name': dom_name,
                            'url': j.value,
                            'source': self.source,
                            'category': self.category,
                        })
        logger.debug("Loaded " + str(len(domain_names)) + " domains from MISP feed " + self.source)
        yield domain_names
