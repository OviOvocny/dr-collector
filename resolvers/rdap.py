"""Self-contained RDAP/WHOIS resolver for the collector, wraps whoisit module with auto bootstrapping and falls back to
whois if needed"""
__author__ = "Adam Horák"

import re
import whoisit
import whoisit.errors
import whoisdomain as whois
import json
from logger import logger
from datatypes import RDAPDomainData, RDAPIPData, RDAPASNData, RDAPEntityData, IPNetwork
from exceptions import *
from typing import Optional


class RDAP:
    def __init__(self):
        if not whoisit.is_bootstrapped():
            load_bootstrap_data()

    def domain(self, domain: str, **kwargs) -> Optional[RDAPDomainData]:
        try:
            return whoisit.domain(domain, **kwargs)
        except BaseException:
            # TODO: fallback to whois
            logger.warning(f'RDAP domain object {domain} does not exist, falling back to whois')
            try:
                w = whois.query(domain)
                if w is None:
                    logger.warning(f'Whois empty for {domain}')
                    return None
                return whois_to_rdap_domain(w)
            except whois.exceptions.WhoisQuotaExceeded:
                logger.critical(f'Whois quota exceeded! (at {domain})')
                raise ResolutionNeedsRetry
            except whois.exceptions.UnknownTld:
                logger.error(f'Unknown TLD for {domain}')
                raise ResolutionImpossible
            except whois.exceptions.WhoisPrivateRegistry:
                logger.error(f'Whois private registry for {domain}')
                raise ResolutionImpossible
            except BaseException:
                logger.error(f'Whois query for {domain} failed')
                raise ResolutionImpossible

    def ip(self, ip: str, **kwargs) -> Optional[RDAPIPData]:
        # raises ResourceDoesNotExist if not found
        try:
            ipdata = whoisit.ip(ip, **kwargs)
            ipdata['network'] = IPNetwork(
                prefix_length=ipdata['network'].prefixlen,
                network_address=str(ipdata['network'].network_address),
                netmask=str(ipdata['network'].netmask),
                broadcast_address=str(ipdata['network'].broadcast_address),
                hostmask=str(ipdata['network'].hostmask)
            )
            return RDAPIPData(**ipdata)
        except whoisit.errors.RateLimitedError:
            raise ResolutionNeedsRetry
        except BaseException:
            raise ResolutionImpossible

    def asn(self, asn: int, **kwargs) -> Optional[RDAPASNData]:
        # raises exc if not found
        return whoisit.asn(asn, **kwargs)

    def entity(self, entity: str, **kwargs) -> Optional[RDAPEntityData]:
        # raises exc if not found
        return whoisit.entity(entity, **kwargs)


def save_bootstrap_data():
    bootstrap_data = whoisit.save_bootstrap_data()
    with open('data/rdap_bootstrap.json', 'w') as f:
        json.dump(bootstrap_data, f)


def bootstrap():
    whoisit.clear_bootstrapping()
    whoisit.bootstrap(overrides=True)
    save_bootstrap_data()


def load_bootstrap_data():
    try:
        with open('data/rdap_bootstrap.json', 'r') as f:
            bootstrap_data = json.load(f)
            whoisit.load_bootstrap_data(bootstrap_data, overrides=True)
            logger.debug('Loaded bootstrap data from file')
            if whoisit.bootstrap_is_older_than(3):
                logger.warning('Bootstrap data is older than 3 days, bootstrapping...')
                bootstrap()
    except BaseException:
        bootstrap()

# WHOIS fallback helpers


def definitely_string(s) -> str:
    if s is None:
        return ''
    return str(s)


def normal_case(string: str):
    result = re.sub('([A-Z])', r' \1', string)
    return result.lower()


def whois_to_rdap_domain(d: whois.Domain) -> RDAPDomainData:
    return RDAPDomainData(
        handle='',
        parent_handle='',
        name=d.name,
        whois_server='',
        type='domain',
        terms_of_service_url='',
        copyright_notice='',
        description=[],
        last_changed_date=d.last_updated,
        registration_date=d.creation_date,
        expiration_date=d.expiration_date,
        rir='',
        url='',
        entities={
            'registrant': [{
                'name': definitely_string(d.registrant)
            }],
            'abuse': [{
                'email': definitely_string(d.abuse_contact)
            }],
            'admin': [{
                'name': definitely_string(d.admin)
            }],
            'registrar': [{
                'name': definitely_string(d.registrar)
            }]
        },
        nameservers=[n.upper() for n in d.name_servers],
        status=list(dict.fromkeys([normal_case(status.split()[0]) for status in d.statuses]))
    )
