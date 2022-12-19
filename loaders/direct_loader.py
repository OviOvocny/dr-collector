"""
Domain name loader - reads a file with domain names... that's it
File in -> List of domain names
"""
__author__ = "Adam Horák"

import re
from typing import List
from logger import logger
from loaders.utils import LoaderUtils as U

class DirectLoader:
  """Local file data loader for the collector"""
  valid_sources = ("plain", "octet-stream", "html", "csv")

  def __init__(self, file: str, tmp_dir = "tmp"):
    self.tmp_dir = tmp_dir
    self.source = file

  def load(self):
    """A generator that just yields the domains found (generator is used for consistency with other loaders)"""
    domain_names: List[str] = []
    with open(self.source, "r", encoding='utf-8', errors='ignore') as f:
      for line in f:
        line = line.strip()
        if line.startswith(U.comment_prefixes) or len(line) == 0:
          continue
        domain = re.search(U.hostname_regex, line)
        if domain:
          domain_names.append(domain.group(0))
      logger.debug("Loaded " + str(len(domain_names)) + " domains from " + self.source)
      yield domain_names