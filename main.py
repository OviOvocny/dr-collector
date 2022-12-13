import click
from mongo import MongoWrapper
from datatypes import empty_domain_data
from logger import logger
import concurrent.futures

from loaders.source_loader import SourceLoader

@click.command()
@click.option('--file', '-f', type=click.Path(exists=True), help='File to import sources from')
@click.option('--label', '-l', type=click.Choice(['blacklisted', 'benign']), help='Label for loaded domains', default='blacklisted')
@click.option('--resolve', '-r', is_flag=True, help='Resolve domains stored in db')
def main(file, label, resolve):
  # show help if no args
  if not file and not resolve:
    click.echo(click.get_current_context().get_help())
    return
  
  if file:
    # ask user what type of file it is
    file_type = click.prompt('File type', type=click.Choice(['csv', 'plain']), default='csv')
    # confirm with user before importing
    if not click.confirm(f'Source domain lists from {file} into {label} collection?', default=True):
      return
    else:
      logger.info(f'Importing sources from {file} into {label} collection')
    # load sources from file
    click.echo(f'Loading sources from {file} ({file_type})...')
    loader = SourceLoader()
    if file_type == 'csv':
      loader.source_csv(file, 1)
    elif file_type == 'plain':
      loader.source_plain(file)
    click.echo(f'Found {loader.source_count()} sources')
    # load and store domains in db
    mongo = MongoWrapper(label)
    for domain_list in loader.load():
      with concurrent.futures.ThreadPoolExecutor(max_workers=300) as executor:
        executor.map(mongo._upsert_one, [empty_domain_data(domain, label) for domain in domain_list])
      # click.echo(f'Converting next {len(domain_list)} domains')
      # mongo.bulk_store([empty_domain_data(domain, label) for domain in domain_list])
  elif resolve:
    print('resolve not implemented yet')

if __name__ == '__main__':
  main()