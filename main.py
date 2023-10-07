import concurrent.futures
import json
import sys
import threading
import time
from math import ceil

import click
import pymongo

import timing
from config import Config
from datatypes import empty_domain_data, DomainData
from loaders import SourceLoader, DirectLoader, MISPLoader
from logger import logger, logger_thread
from mongo import MongoWrapper
from resolvers import resolve_domain, try_domain, update_ips
from stats import get_stats, print_stats, write_stats, write_coords


@click.group()
def cli():
    MongoWrapper.test_connection()


@cli.command('stats', help='Show stats for multiple collections')
@click.option('--collections', '-c', type=str, help='Collections to show stats for',
              multiple=True, default=['misp', 'benign'])
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


@cli.command('load')
@click.argument('file', type=click.Path(exists=True), required=True)
@click.option('--label', '-l', type=str, help='Label for loaded domains', default='benign')
@click.option('--direct', '-d', is_flag=True, help='Load directly from the file')
@click.option('--yes', '-y', is_flag=True, help='Don\'t interact, just start')
def load(file, label, direct, yes):
    """Load sources from FILE and store in db"""
    # ask user what type of file it is
    if yes:
        file_type = 'csv'
    else:
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
            stored, writes = mongo.parallel_store([empty_domain_data(domain, label)
                                                   for domain in domain_list], skip_duplicates=True)
            total_stored += stored
            total_writes += writes
        result = f'Added {total_stored} domains in {total_writes} writes, skipped {total_sourced - total_stored} ' \
                 f'duplicates.'
        click.echo(f'Finished: {result}')
        logger.info(result)
    except ValueError as e:
        if 'unknown url type' in str(e):
            click.echo('Can\'t download. File is probably a domain list. Try again with --direct or -d.', err=True)
        else:
            click.echo(str(e), err=True)


@cli.command('load-misp')
@click.argument('feed', type=click.Choice(list(Config.MISP_FEEDS.keys())))
@click.option('--label', '-l', type=str, help='Label for loaded domains', default='misp')
def load_misp(feed, label):
    """Load domains from MISP feed defined in config and selected by FEED name"""
    loader = MISPLoader(feed)
    mongo = MongoWrapper(label)
    mongo.index_by('domain_name')
    total_sourced = 0
    total_stored = 0
    total_writes = 0
    for domain_list in loader.load():
        total_sourced += len(domain_list)
        stored, writes = mongo.parallel_store([empty_domain_data(domain, label)
                                               for domain in domain_list], skip_duplicates=True)
        total_stored += stored
        total_writes += writes
    result = f'Added {total_stored} domains in {total_writes} writes, skipped {total_sourced - total_stored} ' \
             f'duplicates.'
    click.echo(f'Finished: {result}')
    logger.info(result)


@cli.command('resolve', help='Resolve domains stored in db')
@click.option('--type', '-t', 'resolver_type', type=click.Choice(['basic', 'geo',
                                                                  'rep', 'ports']), help='Data to resolve',
              default='basic')
@click.option('--label', '-l', type=str, help='Label (collection name) for loaded domains', default='benign')
@click.option('--retry-evaluated', '-e', is_flag=True,
              help='Retry resolving fields that have failed before', default=False)
@click.option('--force', '-f', is_flag=True,
              help='Force resolving on domains that have already been resolved', default=False)
@click.option('--limit', '-n', type=int, help='Limit number of domains to resolve', default=0)
@click.option('--sequential', '-s', is_flag=True,
              help='Resolve domains sequentially instead of in parallel', default=False)
@click.option('--yes', '-y', is_flag=True, help='Don\'t interact, just start')
def resolve(resolver_type, label, retry_evaluated, limit, sequential, yes, force):
    """Resolve domains stored in db"""
    mongo = MongoWrapper(label)
    click.echo(f'Looking for domains without {resolver_type} data in {label} collection...')
    # get domains without data
    unresolved: pymongo.cursor.Cursor[DomainData]
    count = 0
    if resolver_type == 'basic':
        unresolved, count = mongo.get_unresolved(retry_evaluated, force, limit=limit)
    elif resolver_type == 'geo':
        unresolved, count = mongo.get_unresolved_geo(retry_evaluated, force, limit=limit)
    elif resolver_type == 'rep':
        unresolved, count = mongo.get_unresolved_rep(retry_evaluated, force, limit=limit)
    elif resolver_type == 'ports':
        unresolved, count = mongo.get_unresolved_ports(retry_evaluated, force, limit=limit)
    else:
        raise RuntimeError('Invalid resolver type')

    if count == 0:
        click.echo('Nothing to resolve')
        return
    # confirm with user before resolving
    click.echo(f'Found {count} domains.')
    if sequential:
        click.echo('Will resolve sequentially. Prepare a few coffees.')
    if resolver_type == 'basic':
        click.echo('Will resolve DNS, RDAP, TLS, IP RDAP.\nAbout 3 minutes per 1000 empty domains, but this varies '
                   'a lot.')
        if not yes:
            if not click.confirm(f'Estimating run time of {ceil(count / 1000) * 3} min. Resolve?', default=True):
                return
    elif resolver_type == 'geo':
        click.echo('Will resolve Geo data.\nIf using an API, it may throttle us.')
        if not yes:
            if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
                return
    elif resolver_type == 'rep':
        click.echo('Will resolve reputation data.\nIf using an API, it may throttle us.')
        if not yes:
            if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
                return
    elif resolver_type == 'ports':
        click.echo('Will scan usual ports for all hosts of found domains.')
        if not yes:
            if not click.confirm(f'Estimating run time of potentially a lot. Resolve?', default=True):
                return

    if Config.ENABLE_TIMING:
        timing.enable_timing()

    # resolve domains
    if sequential:
        with click.progressbar(length=count, show_pos=True, show_percent=True) as resolving:
            i = 0
            for domain in unresolved:
                i += 1
                resolve_domain(domain, i, mongo, resolver_type, retry_evaluated or force)
                resolving.update(1)
        timing.dump()
    else:
        run_parallel_resolving(unresolved, count, mongo, resolve_domain, resolver_type, retry_evaluated or force)


def terminator(executor: concurrent.futures.ThreadPoolExecutor,
               progress, mongo: MongoWrapper, timeout=None):
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
                mongo.cleanup()
                click.echo('DB buffer flushed safely.')
                sys.exit(800)
            else:
                last_pos = progress.pos


@cli.command('fixup-ip-data', help='Ensures that related IP data are populated from all configured record types')
@click.option('--label', '-l', type=str, help='Label (collection name) for loaded domains', default='benign')
@click.option('--all', '-a', type=bool, help='Check all domains, not just those that miss IPs of types '
                                             'present in DNS data', is_flag=True, default=True)
@click.option('--limit', '-n', type=int, help='Limit number of domains to resolve', default=0)
def fixup_ip_data(label: str, all: bool, limit: int):
    mongo = MongoWrapper(label)
    unresolved: pymongo.cursor.Cursor[DomainData]
    unresolved, count = mongo.get_all_cursor(limit) if all else mongo.get_with_missing_ips(limit)

    if count == 0:
        click.echo("Nothing to fix")
        return

    click.echo(f"Found {count} domains")
    run_parallel_resolving(unresolved, count, mongo, update_ips)


@cli.command('try', help='Resolve domain and show results')
@click.argument('domain', type=str)
@click.option('--with-ports', '-p', is_flag=True, help='Scan ports', default=False)
def dry_resolve(domain, with_ports):
    data = try_domain(domain, with_ports)
    click.echo(json.dumps(data, indent=2, default=str))


def run_parallel_resolving(unresolved, count, mongo, exec_func, *args):
    with click.progressbar(length=count, show_pos=True, show_percent=True) as resolving:
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            terminator_thread = threading.Thread(target=terminator, args=(executor, resolving, mongo))
            terminator_thread.start()

            futures = []
            batch = 1
            total_batches = count // Config.MONGO_READ_BATCH_SIZE
            dom_num = 0
            total_done = 0

            for domain in unresolved:
                dom_num += 1
                futures.append(executor.submit(exec_func, domain, dom_num, mongo, *args))

                batch_size = min(Config.MONGO_READ_BATCH_SIZE, count - total_done)
                if len(futures) == batch_size:
                    completed_count = 0
                    logger.info(f"Batch {batch}/{total_batches} starting")
                    try:
                        for completed in concurrent.futures.as_completed(futures, timeout=Config.TIMEOUT_PER_BATCH):
                            # check for errors
                            try:
                                completed.result()
                            except KeyboardInterrupt:
                                raise
                            except BaseException as err:
                                logger_thread.exception(f'Exception in resolving thread in batch #{batch}',
                                                        exc_info=err)
                            # update progress bar
                            resolving.update(1)
                            completed_count += 1
                            total_done += 1
                    except KeyboardInterrupt:
                        logger_thread.warning(f"Interrupted manually")
                        mongo.flush()
                        break
                    except BaseException:  # for some reason, TimeoutError doesn't get caught here
                        logger_thread.error(f"Batch #{batch} didn't complete in {Config.TIMEOUT_PER_BATCH} s")
                        resolving.update(Config.MONGO_READ_BATCH_SIZE - completed_count)
                        mongo.flush()

                    futures.clear()
                    batch += 1

            timing.dump()
            click.echo(f'\nWaiting for terminator... (max 10 seconds)')
            terminator_thread.join(timeout=10)


if __name__ == '__main__':
    cli()
