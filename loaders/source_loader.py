"""
Domain name loader - reads a file with source URIs and loads domain names from them
File in -> List of source file URIs -> Download each file -> Extract domain names -> List of domain names
"""
__author__ = "Adam Horák"

import json
import csv
import os
import re
import urllib.request, urllib.error
import zipfile
from typing import List
from logger import logger

class SourceLoader:
  """Local file data loader for the collector"""
  valid_sources = ("plain", "octet-stream", "html", "csv", "zip")
  comment_prefixes = ("#", ";", "//")
  ip_regex = r"^((?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::)))))|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
  hostname_regex = r"(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]"

  def __init__(self, tmp_dir = "tmp"):
    self.tmp_dir = tmp_dir
    self.sources: List[str] = []

  def _filter_non_links(self):
    """Filters out any sources that don't contain a match for the hostname regex"""
    self.sources = [source for source in self.sources if re.search(self.hostname_regex, source)]

  def source_plain(self, filename: str):
    """Reads the file as plain text and looks for non-empty lines that are not comments"""
    with open(filename, "r") as f:
      for line in f:
        line = line.strip()
        if line.startswith(self.comment_prefixes) or len(line) == 0:
          continue
        self.sources.append(line)
    self._filter_non_links()

  def source_csv(self, filename: str, column: int = 0, delimiter: str = ","):
    """Reads the file as CSV and looks for the specified column"""
    with open(filename, "r") as f:
      reader = csv.reader(f, delimiter=delimiter)
      for row in reader:
        if len(row) > column:
          self.sources.append(row[column])
    self._filter_non_links()

  def source_json(self, filename: str, object_key: str, collection_key = None):
    """
    Reads the file as JSON and looks for the specified keys.
    If collection_key is specified, it will look for the object_key in each object in that collection.
    Else, it will expect the root to be an array of objects and look for the object_key in each object.
    """
    with open(filename, "r") as f:
      data = json.load(f)
      if collection_key is not None:
        if collection_key in data:
          for obj in data[collection_key]:
            if object_key in obj:
              self.sources.append(obj[object_key])
      else:
        for obj in data:
          if object_key in obj:
            self.sources.append(obj[object_key])
    self._filter_non_links()

  def load(self):
    """A generator that, for each source, downloads the contents and yields the domains found"""
    for source in self.sources:
      domain_names: List[str] = []
      try:
        file, info = urllib.request.urlretrieve(source, filename=None)
        type = info.get_content_subtype()
        if type in self.valid_sources:
          if type == "zip":
            file = self._unzip_tmp(file)
          # special edge cases
          if "urlhaus" in source:
            domain_names = self._get_urlhaus(file)
          # other text files
          else:
            domain_names = self._get_txt(file)
          os.remove(file)
          logger.debug("Loaded " + str(len(domain_names)) + " domains from " + source)
          yield domain_names
      except urllib.error.HTTPError as e:
        logger.error(str(e) + " " + source)
      except urllib.error.URLError as e:
        logger.error(str(e) + " " + source)

  def _unzip_tmp(self, file: str):
    """Unzips the file to a temporary directory and returns the path to the unzipped file"""
    with zipfile.ZipFile(file, "r") as zip_ref:
      zip_ref.extractall(self.tmp_dir)
    return self.tmp_dir + "/" + zip_ref.namelist()[0]

  def _get_urlhaus(self, file: str):
    domain_names: List[str] = []
    with open(file, 'r', encoding='utf-8', errors='ignore') as csvf:
      reader = csv.reader(csvf)
      URL_COL = 2 # url column in urlhaus csv
      for row in reader:
        if len(row) > URL_COL:
          domain = re.search(self.hostname_regex, row[URL_COL])
          if domain:
            domain_names.append(domain.group(0))
    return domain_names

  def _get_txt(self, file: str):
    domain_names: List[str] = []
    with open(file, "r", encoding='utf-8', errors='ignore') as f:
      for line in f:
        line = line.strip()
        if line.startswith(self.comment_prefixes) or len(line) == 0:
          continue
        domain = re.search(self.hostname_regex, line)
        if domain:
          domain_names.append(domain.group(0))
    return domain_names
