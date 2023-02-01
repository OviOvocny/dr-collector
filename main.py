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
from resolvers import resolve_domain
from stats import get_stats, print_stats, write_stats, write_coords


@click.group()
def cli():
  MongoWrapper.test_connection()


@cli.command('stats', help='Show stats for multiple collections')
@click.option('--collections', '-c', type=click.Choice(['blacklisted', 'benign']), help='Collections to show stats for', multiple=True, default=['blacklisted', 'benign'])
@click.option('--write', '-w', is_flag=True, help='Write stats to stats.json file')
@click.option('--geo', '-g', is_flag=True, help='Write coords to csv files instead')
def stats(collections, write, geo):
  """Show stats for multiple collections"""
  click.echo('Getting stats...')
  if geo:
    for collection in collections:
      write_coords(collection)
      click.echo(f'Coords written to {collection}.csv')
  else:
    stats = get_stats(collections)
    print_stats(stats)
    if write:
      write_stats(stats)
      click.echo('Stats also written to stats.json')


@cli.command('load', help='Load sources from file, download and store in db')
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
  else:
    logger.info(f'Importing sources from {file} into {label} collection')
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
  mongo.index_by('domain_name')
  total_sourced = 0
  total_stored = 0
  total_writes = 0
  try:
    for domain_list in loader.load():
      total_sourced += len(domain_list)
      stored, writes = mongo.parallel_store([empty_domain_data(domain, label) for domain in domain_list])
      total_stored += stored
      total_writes += writes
    result = f'Added {total_stored} domains in {total_writes} writes, skipped {total_sourced - total_stored} duplicates.'
    click.echo(f'Finished: {result}')
    logger.info(result)
  except ValueError as e:
    if 'unknown url type' in str(e):
      click.echo('Can\'t download. File is probably a domain list. Try again with --direct or -d.', err=True)
    else:
      click.echo(str(e), err=True)


@cli.command('resolve', help='Resolve domains stored in db')
@click.option('--type', '-t', type=click.Choice(['basic', 'geo', 'rep']), help='Data to resolve', default='basic')
@click.option('--label', '-l', type=click.Choice(['blacklisted', 'benign']), help='Label for loaded domains', default='blacklisted')
@click.option('--retry-evaluated', '-e', is_flag=True, help='Retry resolving fields that have failed before', default=False)
@click.option('--limit', '-n', type=int, help='Limit number of domains to resolve', default=0)
@click.option('--sequential', '-s', is_flag=True, help='Resolve domains sequentially instead of in parallel', default=False)
@click.option('--yes', '-y', is_flag=True, help='Don\'t interact, just start')
def resolve(type, label, retry_evaluated, limit, sequential, yes):
  """Resolve domains stored in db"""
  mongo = MongoWrapper(label)
  click.echo(f'Looking for domains without {type} data in {label} collection...')
  # get domains without data
  unresolved = []
  count = 0
  if type == 'basic':
    unresolved, count = mongo.get_unresolved(retry_evaluated, limit=limit)
  elif type == 'geo':
    unresolved, count = mongo.get_unresolved_geo(retry_evaluated, limit=limit)
  elif type == 'rep':
    unresolved, count = mongo.get_unresolved_rep(retry_evaluated, limit=limit)
  elif type == 'ports':
    unresolved, count = mongo.get_unresolved_ports(retry_evaluated, limit=limit)
  if count == 0:
    click.echo('Nothing to resolve')
    return
  # confirm with user before resolving
  click.echo(f'Found {count} domains.')
  if sequential:
    click.echo('Will resolve sequentially. Prepare a few coffees.')
  if type == 'basic':
    click.echo('Will resolve DNS, RDAP, TLS, IP RDAP.\nAbout 3 minutes per 1000 empty domains, but this varies a lot.')
    if not yes:
      if not click.confirm(f'Estimating run time of {ceil(count/1000)*3} min. Resolve?', default=True):
        return
  elif type == 'geo':
    click.echo('Will resolve Geo data.\nIf using an API, it may throttle us.')
    if not yes:
      if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
        return
  elif type == 'rep':
    click.echo('Will resolve reputation data.\nIf using an API, it may throttle us.')
    if not yes:
      if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
        return
  elif type == 'ports':
    click.echo('Will scan usual ports for all hosts of found domains.')
    if not yes:
      if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
        return
  # resolve domains
  if sequential:
    with click.progressbar(length=count, show_pos=True, show_percent=True) as resolving:
      for domain in unresolved:
        resolve_domain(domain, mongo, type, retry_evaluated)
        resolving.update(1)
  else:
    with click.progressbar(length=count, show_pos=True, show_percent=True) as resolving:
      with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        terminator_thread = threading.Thread(target=terminator, args=(executor, resolving, mongo))
        terminator_thread.start()
        futures = [executor.submit(resolve_domain, domain, mongo, type, retry_evaluated) for domain in unresolved]
        for _ in concurrent.futures.as_completed(futures):
          resolving.update(1)
        click.echo(f'Waiting for terminator... (max 10 seconds)')
        terminator_thread.join()

def terminator(executor: concurrent.futures.ThreadPoolExecutor, progress: ProgressBar, mongo: MongoWrapper, timeout = None):
  _timeout = timeout if timeout else Config.TERMINATOR
  sleeptime = 10
  naps = _timeout // sleeptime
  last_pos = progress.pos
  napped = 0
  while True:
    time.sleep(sleeptime)
    napped += 1
    if progress.finished:
      break
    elif napped == naps:
      napped = 0
      if progress.pos == last_pos:
        click.echo(f'No progress for {_timeout} seconds. Terminating...')
        logger.debug(f'No progress for {_timeout} seconds. Run terminated.')
        executor.shutdown(wait=False, cancel_futures=True)
        mongo._cleanup()
        click.echo('DB buffer flushed safely.')
        os._exit(800)
      else:
        last_pos = progress.pos

if __name__ == '__main__':
  cli()