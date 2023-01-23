from collections import Counter
import click
from click._termui_impl import ProgressBar
import time
import threading
import os
import concurrent.futures
from math import ceil
from config import Config
from mongo import MongoWrapper
from datatypes import empty_domain_data
from logger import logger
from exceptions import *

from loaders import SourceLoader, DirectLoader


@click.group()
def cli():
  MongoWrapper.test_connection()


@cli.command('update', help='Load sources from file, download and store in db')
@click.option('--file', '-f', type=click.Path(exists=True), help='File to import sources from')
@click.option('--label', '-l', type=click.Choice(['blacklisted', 'benign']), help='Label for loaded domains', default='blacklisted')
@click.option('--direct', '-d', is_flag=True, help='Load directly from the file')
@click.option('--yes', '-y', is_flag=True, help='Don\'t interact, just start')
def load(file, label, direct, yes):
  """Load sources from file and store in db"""
  # ask user what type of file it is
  file_type = click.prompt('File type', type=click.Choice(['csv', 'plain']), default='csv')
  # confirm with user before importing
  if not yes:
    if not click.confirm(f'Load domain list(s) from {file} into {label} collection?', default=True):
      return
  # load sources from file
  click.echo(f'Loading sources from {file} ({file_type})...')
  if direct:
    loader = DirectLoader(file)
  else:
    loader = SourceLoader()
    if file_type == 'csv':
      loader.source_csv(file, column=1, category=5, category_source=6, getter=7, mapper=8)
    elif file_type == 'plain':
      loader.source_plain(file)
    click.echo(f'Found {loader.source_count()} sources')
  # load and store domains in db
  mongo = MongoWrapper(label)
  total_sourced = 0
  total_stored = 0
  total_writes = 0
  try:
    for domain_list in loader.load():
      total_sourced += len(domain_list)
      for domain in domain_list:
        result = mongo._collection.update_one({'domain_name': domain['name']}, {'$set': {
          'source': domain['source'],
          'category': domain['category'],
        }})
        total_stored += result.modified_count
    result = f'Added data to {total_stored} domains, skipped {total_sourced - total_stored} duplicates.'
    click.echo(f'Finished: {result}')
  except ValueError as e:
    if 'unknown url type' in str(e):
      click.echo('Can\'t download. File is probably a domain list. Try again with --direct or -d.', err=True)
    else:
      click.echo(str(e), err=True)

if __name__ == '__main__':
  cli()