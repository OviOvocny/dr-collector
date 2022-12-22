from math import ceil
import click
import concurrent.futures
from datetime import datetime
from config import Config
from mongo import MongoWrapper
from datatypes import empty_domain_data, empty_ip_data, DomainData, IPData
from logger import logger
from whois.exceptions import WhoisQuotaExceeded
from exceptions import *

from loaders import SourceLoader, DirectLoader
from resolvers import DNS, RDAP, TLS, GeoIP2, NERD


@click.group()
def cli():
  MongoWrapper.test_connection()


@cli.command('load', help='Load sources from file, download and store in db')
@click.option('--file', '-f', type=click.Path(exists=True), help='File to import sources from')
@click.option('--label', '-l', type=click.Choice(['blacklisted', 'benign']), help='Label for loaded domains', default='blacklisted')
@click.option('--direct', '-d', is_flag=True, help='Load directly from the file')
def load(file, label, direct):
  """Load sources from file and store in db"""
  # ask user what type of file it is
  file_type = click.prompt('File type', type=click.Choice(['csv', 'plain']), default='csv')
  # confirm with user before importing
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
      loader.source_csv(file, 1)
    elif file_type == 'plain':
      loader.source_plain(file)
    click.echo(f'Found {loader.source_count()} sources')
  # load and store domains in db
  mongo = MongoWrapper(label)
  total_sourced = 0
  total_stored = 0
  total_writes = 0
  for domain_list in loader.load():
    total_sourced += len(domain_list)
    stored, writes = mongo.parallel_store([empty_domain_data(domain, label) for domain in domain_list])
    total_stored += stored
    total_writes += writes
  result = f'Added {total_stored} domains in {total_writes} s, skipped {total_sourced - total_stored} duplicates.'
  click.echo(f'Finished: {result}')
  logger.info(result)


@cli.command('resolve', help='Resolve domains stored in db')
@click.option('--resolve', '-r', type=click.Choice(['basic', 'geo', 'rep']), help='Data to resolve', default='basic')
@click.option('--label', '-l', type=click.Choice(['blacklisted', 'benign']), help='Label for loaded domains', default='blacklisted')
@click.option('--retry-evaluated', '-e', is_flag=True, help='Retry resolving fields that have failed before', default=False)
@click.option('--limit', '-n', type=int, help='Limit number of domains to resolve', default=0)
@click.option('--sequential', '-s', is_flag=True, help='Resolve domains sequentially instead of in parallel', default=False)
def resolve(resolve, label, retry_evaluated, limit, sequential):
  """Resolve domains stored in db"""
  mongo = MongoWrapper(label)
  click.echo(f'Looking for domains without {resolve} data in {label} collection...')
  # get domains without data
  unresolved = []
  if resolve == 'basic':
    unresolved = mongo.get_unresolved(retry_evaluated, limit=limit)
  elif resolve == 'geo':
    unresolved = mongo.get_unresolved_geo(retry_evaluated, limit=limit)
  elif resolve == 'rep':
    unresolved = mongo.get_unresolved_rep(retry_evaluated, limit=limit)
  if len(unresolved) == 0:
    click.echo('Nothing to resolve')
    return
  # confirm with user before resolving
  click.echo(f'Found {len(unresolved)} domains.')
  if sequential:
    click.echo('Will resolve sequentially. Prepare a few coffees.')
  if resolve == 'basic':
    click.echo('Will resolve DNS, RDAP, TLS, IP RDAP.\nAbout 3 minutes per 1000 empty domains, but this varies a lot.')
    if not click.confirm(f'Estimating run time of {ceil(len(unresolved)/1000)*3} min. Resolve?', default=True):
      return
  elif resolve == 'geo':
    click.echo('Will resolve Geo data.\nIf using an API, it may throttle us.')
    if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
      return
  elif resolve == 'rep':
    click.echo('Will resolve reputation data.\nIf using an API, it may throttle us.')
    if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
      return
  # resolve domains
  if sequential:
    with click.progressbar(unresolved, show_pos=True, show_percent=True) as resolving:
      for domain in resolving:
        resolve_domain(domain, mongo, resolve, retry_evaluated)
  else:
    with click.progressbar(length=len(unresolved), show_pos=True, show_percent=True) as resolving:
      with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        futures = [executor.submit(resolve_domain, domain, mongo, resolve, retry_evaluated) for domain in unresolved]
        for _ in concurrent.futures.as_completed(futures):
          resolving.update(1)


def resolve_domain(domain: DomainData, mongo: MongoWrapper, mode: str = 'basic', retry_evaluated = False):
  """Resolve domain basic info and store results in db"""
  name = domain['domain_name']
  # set up resolvers
  rdap = RDAP()

  if mode == 'basic':
    # resolve DNS if needed
    if domain['remarks']['dns_evaluated_on'] is None or retry_evaluated:
      dns = DNS()
      try:
        domain['dns'], ips = dns.query(name)
        domain['remarks']['dns_evaluated_on'] = datetime.now()
        domain['remarks']['dns_had_no_ips'] = ips is None
        if ips is not None:
          if domain['ip_data'] is None:
            domain['ip_data'] = []
          for ip in ips:
            if not any(ip_data['ip'] == ip for ip_data in domain['ip_data']):
              domain['ip_data'].append(empty_ip_data(ip))
      except ResolutionImpossible:
        domain['dns'] = None
        domain['remarks']['dns_evaluated_on'] = datetime.now()
        domain['remarks']['dns_had_no_ips'] = False
      except ResolutionNeedsRetry:
        domain['remarks']['dns_evaluated_on'] = None

    # resolve RDAP if needed
    if domain['remarks']['rdap_evaluated_on'] is None or retry_evaluated:
      try:
        domain['rdap'] = rdap.domain(name)
        domain['remarks']['rdap_evaluated_on'] = datetime.now()
      except ResolutionImpossible:
        domain['rdap'] = None
        domain['remarks']['rdap_evaluated_on'] = datetime.now()
      except ResolutionNeedsRetry:
        domain['remarks']['rdap_evaluated_on'] = None

    # resolve TLS if needed
    if domain['remarks']['tls_evaluated_on'] is None or retry_evaluated:
      tls = TLS()
      try:
        domain['tls'] = tls.resolve(name)
      except ResolutionImpossible:
        domain['tls'] = None
      except ResolutionNeedsRetry:
        # immediately retry for timeouts, last chance
        try:
          domain['tls'] = tls.resolve(name, timeout=2)
        except: #anything
          domain['tls'] = None
      finally:
        domain['remarks']['tls_evaluated_on'] = datetime.now()

    # resolve IP RDAP if needed
    if domain['ip_data'] is not None:
      for ip_data in domain['ip_data']:
        if ip_data['rdap'] is None:
          try:
            ip_data['rdap'] = rdap.ip(ip_data['ip'])
            ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
          except ResolutionImpossible:
            ip_data['rdap'] = None
            ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
          except ResolutionNeedsRetry:
            ip_data['remarks']['rdap_evaluated_on'] = None

    # mark evaluated time
    domain['evaluated_on'] = datetime.now()

  elif mode == 'geo':
    if domain['ip_data'] is not None:
      geo = GeoIP2()
      for ip_data in domain['ip_data']:
        if ip_data['remarks']['geo_evaluated_on'] is None or retry_evaluated:
          try:
            ip_data['geo'] = geo.single(ip_data['ip'])
            ip_data['remarks']['geo_evaluated_on'] = datetime.now()
          except ResolutionImpossible:
            ip_data['geo'] = None
            ip_data['remarks']['geo_evaluated_on'] = datetime.now()
          except ResolutionNeedsRetry:
            ip_data['remarks']['geo_evaluated_on'] = None

  elif mode == 'rep':
    if domain['ip_data'] is not None:
      nerd = NERD(respect_bucket=True) # respect bucket will not help in parallel mode!!
      for ip_data in domain['ip_data']:
        if ip_data['remarks']['rep_evaluated_on'] is None or retry_evaluated:
          if ip_data['rep'] is None:
            ip_data['rep'] = {}
          try:
            ip_data['rep']['nerd'] = nerd.resolve(ip_data['ip'])
            ip_data['remarks']['rep_evaluated_on'] = datetime.now()
          except ResolutionImpossible:
            ip_data['rep']['nerd'] = None
            ip_data['remarks']['rep_evaluated_on'] = datetime.now()
          except ResolutionNeedsRetry:
            ip_data['remarks']['rep_evaluated_on'] = None

  # store results
  mongo.store(domain)



if __name__ == '__main__':
  cli()