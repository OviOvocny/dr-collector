import click

from loaders import SourceLoader, DirectLoader
from mongo import MongoWrapper


@click.group()
def cli():
    MongoWrapper.test_connection()


@cli.command('update', help='Load sources from file, download and store in db')
@click.option('--file', '-f', type=click.Path(exists=True), help='File to import sources from')
@click.option('--label', '-l', type=click.Choice(['blacklisted', 'benign']),
              help='Label for loaded domains', default='blacklisted')
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
            with click.progressbar(domain_list, label='Storing domains', show_pos=True, show_percent=False) as bar:
                for domain in bar:
                    result = mongo.update_one({'domain_name': domain['name']}, {'$set': {
                        'source': domain['source'],
                        'category': domain['category'],
                    }})
                    total_stored += result.modified_count
                    bar.label = f'Storing domains ({total_stored} stored)'
        result = f'Added data to {total_stored} domains.'
        click.echo(f'Finished: {result}')
    except ValueError as e:
        if 'unknown url type' in str(e):
            click.echo('Can\'t download. File is probably a domain list. Try again with --direct or -d.', err=True)
        else:
            click.echo(str(e), err=True)


if __name__ == '__main__':
    cli()
