# import all resolvers
import sys
from typing import List, Optional

import dr_collector.config
import dr_collector.timing as timing
from .asn import ASN
from .dns import DNS
from .rdap import RDAP
from .tls import TLS
from .icmp import ICMP
from .ports import PortScan

from .geo.geoip2_resolver import Geo as GeoIP2
from .geo.universal_api import Geo as GeoAPI

from .rep.nerd import NERD

# import other stuff for main resolver
from dr_collector.exceptions import *
from dr_collector.datatypes import DomainData, empty_ip_data, empty_domain_data, IPFromDNS
from dr_collector.mongo import MongoWrapper
from datetime import datetime
from dr_collector.logger import logger

# some stuff for dry run
import re
from dr_collector.loaders.utils import LoaderUtils as U


def resolve_single(domain_name: str) -> DomainData:
    name = domain_name
    rdap = RDAP()
    dns = DNS()
    tls = TLS()
    asn = ASN()
    icmp = ICMP()
    geo = GeoIP2()

    domain = empty_domain_data({
        'name': domain_name,
        'url': "",
        'source': "cli",
        'category': "unknown"
    }, "cli")

    domain['evaluated_on'] = datetime.now()

    try:
        print("Collecting DNS data", file=sys.stderr)
        domain['remarks']['dns_evaluated_on'] = datetime.now()
        domain['dns'], ips = dns.query(name)
        domain['remarks']['dns_had_no_ips'] = ips is None or len(ips) == 0
        dns.close_socket()

        if ips is not None:
            if domain['ip_data'] is None:
                domain['ip_data'] = []

            for ip in ips:
                if any(ip_data['ip'] == ip.ip for ip_data in domain['ip_data']):
                    continue

                ip_data = empty_ip_data(ip)
                ip_val = ip.ip

                try:
                    print(f"Collecting RDAP data for IP {ip_val}", file=sys.stderr)
                    ip_data['rdap'] = rdap.ip(ip_val)
                    ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
                except Exception as e:
                    print(str(e), file=sys.stderr)

                try:
                    print(f"Collecting ICMP data for IP {ip_val}", file=sys.stderr)
                    ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = icmp.ping(ip_val)
                    ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
                except Exception as e:
                    print(str(e), file=sys.stderr)

                try:
                    print(f"Collecting ASN data for IP {ip_val}", file=sys.stderr)
                    ip_data['asn'] = asn.single(ip_val)
                    ip_data['remarks']['asn_evaluated_on'] = datetime.now()
                except Exception as e:
                    print(str(e), file=sys.stderr)

                try:
                    print(f"Collecting GeoIP data for IP {ip_val}", file=sys.stderr)
                    ip_data['geo'] = geo.single(ip_val)
                    ip_data['remarks']['geo_evaluated_on'] = datetime.now()
                except Exception as e:
                    print(str(e), file=sys.stderr)

                try:
                    nerd = NERD()
                    print(f"Collecting NERD data for IP {ip_val}", file=sys.stderr)
                    ip_data['rep']['nerd'] = nerd.resolve(ip_data['ip'])
                    ip_data['remarks']['rep_evaluated_on'] = datetime.now()
                except Exception as e:
                    print(str(e), file=sys.stderr)

                domain['ip_data'].append(ip_data)

    except Exception as e:
        print(str(e), file=sys.stderr)

    try:
        print("Collecting RDAP data", file=sys.stderr)
        domain['remarks']['rdap_evaluated_on'] = datetime.now()
        domain['rdap'] = rdap.domain(name)
    except Exception as e:
        print(str(e), file=sys.stderr)

    try:
        print("Collecting TLS data", file=sys.stderr)
        domain['remarks']['tls_evaluated_on'] = datetime.now()
        domain['tls'] = tls.resolve(name)
    except Exception as e:
        print(str(e), file=sys.stderr)

    return domain


@timing.time_exec
def resolve_domain(domain: DomainData, domain_index: int, mongo: MongoWrapper, mode: str = 'basic',
                   retry_evaluated=False):
    """Resolve domain basic info and store results in db"""
    name = domain['domain_name']
    logger.info(f"Resolving {name} (#{domain_index})")
    # set up resolvers
    rdap = RDAP()

    if mode == 'basic':
        # resolve DNS if needed
        if retry_evaluated or domain['remarks']['dns_evaluated_on'] is None:
            logger.info(f"Resolving DNS for {name} (#{domain_index})")
            dns = DNS()
            try:
                domain['remarks']['dns_evaluated_on'] = datetime.now()
                domain['dns'], ips = dns.query(name)
                domain['remarks']['dns_had_no_ips'] = ips is None or len(ips) == 0
                if ips is not None:
                    if domain['ip_data'] is None:
                        domain['ip_data'] = []
                    for ip in ips:
                        if not any(ip_data['ip'] == ip.ip for ip_data in domain['ip_data']):
                            domain['ip_data'].append(empty_ip_data(ip))
            except ResolutionImpossible:
                domain['dns'] = None
                domain['remarks']['dns_had_no_ips'] = False
            except ResolutionNeedsRetry:
                domain['remarks']['dns_evaluated_on'] = None
            except BaseException as err:
                domain['dns'] = None
                domain['remarks']['dns_evaluated_on'] = None
                logger.error(f"DNS resolver uncaught error for {name}", exc_info=err)
            dns.close_socket()

        # resolve RDAP if needed
        if retry_evaluated or domain['remarks']['rdap_evaluated_on'] is None:
            logger.info(f"Resolving RDAP for {name} (#{domain_index})")
            try:
                domain['remarks']['rdap_evaluated_on'] = datetime.now()
                domain['rdap'] = rdap.domain(name)
            except ResolutionImpossible:
                domain['rdap'] = None
            except ResolutionNeedsRetry:
                domain['remarks']['rdap_evaluated_on'] = None
            except BaseException as err:
                domain['rdap'] = None
                domain['remarks']['rdap_evaluated_on'] = None
                logger.error(f"RDAP resolver uncaught error for {name}", exc_info=err)

        # resolve TLS if needed
        if retry_evaluated or domain['remarks']['tls_evaluated_on'] is None:
            logger.info(f"Resolving TLS for {name} (#{domain_index})")
            tls = TLS()
            try:
                domain['remarks']['tls_evaluated_on'] = datetime.now()
                domain['tls'] = tls.resolve(name)
            except ResolutionImpossible:
                domain['tls'] = None
            except ResolutionNeedsRetry:
                # immediately retry for timeouts, last chance
                try:
                    domain['tls'] = tls.resolve(name, timeout=2)
                except BaseException:  # anything
                    domain['tls'] = None
                    domain['remarks']['tls_evaluated_on'] = None
            except BaseException as err:
                domain['tls'] = None
                domain['remarks']['tls_evaluated_on'] = None
                logger.error(f"TLS resolver uncaught error for {name}", exc_info=err)

        # resolve IP RDAP and alive status if needed
        if domain['ip_data'] is not None:
            logger.info(f"Resolving IP data for {name} (#{domain_index})")
            icmp = ICMP()
            asn = ASN()

            for ip_data in domain['ip_data']:
                ip_val = ip_data['ip']
                # resolve RDAP
                if retry_evaluated or ip_data['remarks']['rdap_evaluated_on'] is None:
                    logger.debug(f"Resolving RDAP for {ip_val} (#{domain_index})")
                    try:
                        ip_data['rdap'] = rdap.ip(ip_val)
                        ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
                    except ResolutionImpossible:
                        ip_data['rdap'] = None
                        ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
                    except ResolutionNeedsRetry:
                        ip_data['remarks']['rdap_evaluated_on'] = None
                    except BaseException as err:
                        domain['rdap'] = None
                        domain['remarks']['rdap_evaluated_on'] = None
                        logger.error(f"RDAP resolver uncaught error for {ip_val}", exc_info=err)

                # resolve alive status
                if retry_evaluated or ip_data['remarks']['icmp_evaluated_on'] is None:
                    logger.debug(f"Pinging {ip_val} (#{domain_index})")
                    try:
                        ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = icmp.ping(ip_val)
                        ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
                    except ResolutionImpossible:
                        ip_data['remarks']['is_alive'] = False
                        ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
                    except ResolutionNeedsRetry:
                        ip_data['remarks']['icmp_evaluated_on'] = None

                # resolve ASN information
                if retry_evaluated or 'asn_evaluated_on' not in ip_data['remarks'] or \
                        ip_data['remarks']['asn_evaluated_on'] is None:
                    logger.debug(f"Resolving ASN for {ip_val} (#{domain_index})")
                    try:
                        ip_data['asn'] = asn.single(ip_val)
                        ip_data['remarks']['asn_evaluated_on'] = datetime.now()
                    except ResolutionImpossible:
                        ip_data['asn'] = None
                        ip_data['remarks']['asn_evaluated_on'] = datetime.now()
                    except ResolutionNeedsRetry:
                        ip_data['remarks']['asn_evaluated_on'] = None

        # mark evaluated time
        domain['evaluated_on'] = datetime.now()

    elif mode == 'geo':
        if domain['ip_data'] is not None:
            geo = GeoIP2()
            for ip_data in domain['ip_data']:
                if retry_evaluated or ip_data['remarks']['geo_evaluated_on'] is None:
                    logger.debug(f"Resolving GEO for {ip_data['ip']} (#{domain_index})")
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
            nerd = NERD(respect_bucket=True)  # respect bucket will not help in parallel mode!!
            for ip_data in domain['ip_data']:
                if retry_evaluated or ip_data['remarks']['rep_evaluated_on'] is None:
                    logger.debug(f"Resolving NERD for {ip_data['ip']} (#{domain_index})")
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

    elif mode == 'ports':
        if domain['ip_data'] is not None:
            scanner = PortScan()
            for ip_data in domain['ip_data']:
                if retry_evaluated or ip_data['remarks']['ports_scanned_on'] is None:
                    logger.debug(f"Scanning ports for {ip_data['ip']} (#{domain_index})")
                    ip_data['ports'] = scanner.scan(ip_data['ip'])  # TODO add option to specify ports
                    ip_data['remarks']['ports_scanned_on'] = datetime.now()

    logger.info(f"Domain {name} (#{domain_index}) done")
    # store results
    mongo.store(domain)


def update_ips(domain: DomainData, domain_index: int, mongo: MongoWrapper):
    dns_data = domain['dns']
    if dns_data is None or domain['remarks']['dns_evaluated_on'] is None:
        return

    name = domain['domain_name']
    logger.info(f"Checking {name} (#{domain_index})")

    ips = []

    for rec_type in config.Config.COLLECT_IPS_FROM:
        if rec_type in dns_data and dns_data[rec_type] is not None:
            rec = dns_data[rec_type]
            if rec_type == 'A' or rec_type == 'AAAA':
                ips.extend(IPFromDNS(x, rec_type) for x in rec)
            elif rec_type == 'CNAME' and 'related_ips' in rec and rec['related_ips'] is not None:
                ips.extend(IPFromDNS(x['value'], rec_type) for x in rec['related_ips'])
            elif rec_type == 'MX' or rec_type == 'NS':
                for v in rec.values():
                    if 'related_ips' in v and v['related_ips'] is not None:
                        ips.extend(IPFromDNS(x['value'], rec_type) for x in v['related_ips'])

    if len(ips) == 0:
        return

    ip_data = (domain['ip_data'] if 'ip_data' in domain else []) or []
    found_set = set()
    for existing_ip in ip_data:
        found_set.add(existing_ip['ip'])

    written = 0
    for ip in ips:
        if ip.ip not in found_set:
            ip_data.append(empty_ip_data(ip))
            written += 1
            found_set.add(ip.ip)

    logger.info(f"[#{domain_index}] Wrote {written} IPs")
    domain['ip_data'] = ip_data
    # store results
    mongo.store(domain)


@timing.time_exec
def try_domain(domain: str, scan_ports=False) -> DomainData:
    """Resolve domain without storing results."""
    # init all resolvers
    dns = DNS()
    rdap = RDAP()
    asn = ASN()
    tls = TLS()
    icmp = ICMP()
    geo = GeoIP2()
    nerd = NERD()
    scanner = PortScan()
    # init domain data
    domain_name = re.search(U.hostname_regex, domain)
    if not domain_name:
        print('Invalid domain name')
        exit(1)
    #
    name = domain_name.group(0)  # type: str
    domain_data = empty_domain_data({
        'name': name,
        'url': domain,
        'source': 'try_domain',
        'category': 'try_domain'
    }, 'test')

    logger.debug(f"Resolving DNS for {name}")
    # resolve DNS
    try:
        dns_data, ips = dns.query(name)
        domain_data['dns'] = dns_data
        domain_data['remarks']['dns_evaluated_on'] = datetime.now()
        if ips is None:
            domain_data['remarks']['dns_had_no_ips'] = True
        else:
            domain_data['remarks']['dns_had_no_ips'] = False
            domain_data['ip_data'] = []
            for ip in ips:
                domain_data['ip_data'].append(empty_ip_data(ip))
    except ResolutionImpossible:
        domain_data['dns'] = None
        domain_data['remarks']['dns_evaluated_on'] = datetime.now()
        domain_data['remarks']['dns_had_no_ips'] = False
    except ResolutionNeedsRetry:
        domain_data['remarks']['dns_evaluated_on'] = None
        domain_data['remarks']['dns_had_no_ips'] = False
    dns.close_socket()

    logger.debug(f"Resolving RDAP for {name}")
    # resolve RDAP
    try:
        domain_data['rdap'] = rdap.domain(name)
        domain_data['remarks']['rdap_evaluated_on'] = datetime.now()
    except ResolutionImpossible:
        domain_data['rdap'] = None
        domain_data['remarks']['rdap_evaluated_on'] = datetime.now()
    except ResolutionNeedsRetry:
        domain_data['remarks']['rdap_evaluated_on'] = None

    logger.debug(f"Resolving TLS for {name}")
    # resolve TLS
    try:
        domain_data['tls'] = tls.resolve(name)
        domain_data['remarks']['tls_evaluated_on'] = datetime.now()
    except ResolutionImpossible:
        domain_data['tls'] = None
        domain_data['remarks']['tls_evaluated_on'] = datetime.now()
    except ResolutionNeedsRetry:
        domain_data['remarks']['tls_evaluated_on'] = None

    logger.debug(f"Resolving IPs for {name}")
    # IPs
    if domain_data['ip_data'] is not None:
        for ip_data in domain_data['ip_data']:
            ip_data['rep'] = {}

            logger.debug(f"Pinging {ip_data}")
            # try ICMP ping
            try:
                ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = icmp.ping(ip_data['ip'])
                ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
            except ResolutionImpossible:
                ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = False, None
                ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
            except ResolutionNeedsRetry:
                ip_data['remarks']['icmp_evaluated_on'] = None

            logger.debug(f"Resolving RDAP for {ip_data}")
            # resolve RDAP
            try:
                ip_data['rdap'] = rdap.ip(ip_data['ip'])
                ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
            except ResolutionImpossible:
                ip_data['rdap'] = None
                ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
            except ResolutionNeedsRetry:
                ip_data['remarks']['rdap_evaluated_on'] = None

            logger.debug(f"Resolving ASN for {ip_data}")
            # resolve ASN information
            try:
                ip_data['asn'] = asn.single(ip_data['ip'])
                ip_data['remarks']['asn_evaluated_on'] = datetime.now()
            except ResolutionImpossible:
                ip_data['asn'] = None
                ip_data['remarks']['asn_evaluated_on'] = datetime.now()
            except ResolutionNeedsRetry:
                ip_data['remarks']['asn_evaluated_on'] = None

            logger.debug(f"Resolving GEO for {ip_data}")
            # resolve geo
            try:
                ip_data['geo'] = geo.single(ip_data['ip'])
                ip_data['remarks']['geo_evaluated_on'] = datetime.now()
            except ResolutionImpossible:
                ip_data['geo'] = None
                ip_data['remarks']['geo_evaluated_on'] = datetime.now()
            except ResolutionNeedsRetry:
                ip_data['remarks']['geo_evaluated_on'] = None

            logger.debug(f"Resolving NERD for {ip_data}")
            # resolve reputation
            try:
                ip_data['rep']['nerd'] = nerd.resolve(ip_data['ip'])
                ip_data['remarks']['rep_evaluated_on'] = datetime.now()
            except ResolutionImpossible:
                ip_data['rep']['nerd'] = None
                ip_data['remarks']['rep_evaluated_on'] = datetime.now()
            except ResolutionNeedsRetry:
                ip_data['remarks']['rep_evaluated_on'] = None

            logger.debug(f"Resolving ports for {ip_data}")
            # resolve ports
            if scan_ports:
                try:
                    ip_data['ports'] = scanner.scan(ip_data['ip'])  # TODO add option to specify ports
                    ip_data['remarks']['ports_scanned_on'] = datetime.now()
                except ResolutionImpossible:
                    ip_data['ports'] = []
                    ip_data['remarks']['ports_scanned_on'] = datetime.now()
                except ResolutionNeedsRetry:
                    ip_data['remarks']['ports_scanned_on'] = None
            else:
                ip_data['ports'] = []
                ip_data['remarks']['ports_scanned_on'] = None

    # return results
    return domain_data
