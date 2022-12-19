from math import ceil
import click
import concurrent.futures
from datetime import datetime
from config import Config
from mongo import MongoWrapper
from datatypes import empty_domain_data, DomainData, IPData
from logger import logger
from whois.exceptions import WhoisQuotaExceeded

from loaders import SourceLoader, DirectLoader
from resolvers import DNS, RDAP, TLS, GeoIP2

# set up resolvers
dns = DNS()
rdap = RDAP()
tls = TLS()
geo = GeoIP2()


@click.group()
def cli():
  pass


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
def resolve(resolve, label, retry_evaluated):
  """Resolve domains stored in db"""
  mongo = MongoWrapper(label)
  click.echo(f'Looking for domains without {resolve} data in {label} collection...')
  # get domains without data
  unresolved = []
  if resolve == 'basic':
    unresolved = mongo.get_unresolved(retry_evaluated)
  elif resolve == 'geo':
    unresolved = mongo.get_unresolved_geo(retry_evaluated)
  elif resolve == 'rep':
    #unresolved = mongo.get_unresolved_rep(retry_evaluated)
    pass
  if len(unresolved) == 0:
    click.echo('Nothing to resolve')
    return
  # confirm with user before resolving
  click.echo(f'Found {len(unresolved)} domains.')
  if resolve == 'basic':
    click.echo('Will resolve DNS, RDAP, TLS, IP RDAP.\nAbout 3 minutes per 1000 empty domains, but this varies a lot.')
    if not click.confirm(f'Estimating run time of {ceil(len(unresolved)/1000)*3} min. Resolve?', default=True):
      return
  elif resolve == 'geo':
    click.echo('Will resolve Geo data.\nIf using an API, it may throttle us.')
    if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
      return
  # resolve domains
  with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
    futures = [executor.submit(resolve_domain, domain, mongo, resolve, retry_evaluated) for domain in unresolved]
    complete = 0
    click.echo(f'\r[{"#" * int(complete / len(unresolved) * 10)}{" " * (10 - int(complete / len(unresolved) * 10))}] {int(complete / len(unresolved) * 100)}%', nl=False)
    for _ in concurrent.futures.as_completed(futures):
      complete += 1
      # progress bar that updates every 100 domains
      if complete % (len(unresolved) // 100) == 0:
        click.echo(f'\r[{"#" * int(complete / len(unresolved) * 10)}{" " * (10 - int(complete / len(unresolved) * 10))}] {int(complete / len(unresolved) * 100)}%', nl=False)


def resolve_domain(domain: DomainData, mongo: MongoWrapper, mode: str = 'basic', retry_evaluated = False):
  """Resolve domain basic info and store results in db"""
  name = domain['domain_name']

  if mode == 'basic':
    if domain['dns'] is None:
      domain['dns'], ips = dns.query(name)
      if ips is not None:
        if domain['ip_data'] is None:
          domain['ip_data'] = []
        for ip in ips:
          if not any(ip_data['ip'] == ip for ip_data in domain['ip_data']):
            domain['ip_data'].append(IPData(ip=ip, rdap=None, rep=None, geo=None, geo_evaluated_on=None, rep_evaluated_on=None))
    if domain['rdap_evaluated_on'] is None or retry_evaluated:
      try:
        domain['rdap'] = rdap.domain(name)
        domain['rdap_evaluated_on'] = datetime.now()
      except WhoisQuotaExceeded:
        domain['rdap_evaluated_on'] = None
    if domain['tls_evaluated_on'] is None or retry_evaluated:
      domain['tls'] = tls.resolve(name)
      domain['tls_evaluated_on'] = datetime.now()
    if domain['ip_data'] is not None:
      for ip_data in domain['ip_data']:
        if ip_data['rdap'] is None:
          ip_data['rdap'] = rdap.ip(ip_data['ip'])
    domain['evaluated_on'] = datetime.now()

  elif mode == 'geo':
    if domain['ip_data'] is not None:
      for ip_data in domain['ip_data']:
        if ip_data['geo_evaluated_on'] is None or retry_evaluated:
          ip_data['geo'] = geo.single(ip_data['ip'])
          ip_data['geo_evaluated_on'] = datetime.now()

  elif mode == 'rep':
    pass

  # store results
  mongo.store(domain)



if __name__ == '__main__':
  cli()