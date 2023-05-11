import json
import re
from datetime import datetime
from mongo import MongoWrapper
from typing import TypedDict, Optional, List, Dict, Tuple, Literal
import math
from statistics import median, mode, mean, multimode
from collections import Counter

possibly_missing = Literal['dns', 'dns.mx', 'dns.a', 'rdap', 'tls', 'ip_data', 'ip_data.geo', 'ip_data.rdap']
lex_features = Literal['entropy', 'number_count', 'domain_levels']

txt_verified_strings = [
  'v=spf1',
  'google-site-verification',
  'atlassian-domain-verification',
  'apple-domain-verification',
  'facebook-domain-verification',
  'onetrust-domain-verification',
  'globalsign-smime-dv'
]

class Stats(TypedDict):
  collection: str
  total: int
  missing: Dict[possibly_missing, int] # missing data counts
  txt_verification_present_count: int
  txt_verifications: Dict[str, int] # txt verification counts
  rdap_last_change_median: float
  most_common_tlds: List[Tuple[str, int]]
  most_common_registrars: List[Tuple[str, int]]
  most_common_countries: List[Tuple[str, int]]
  most_common_tls_authorities: List[Tuple[str, int]]
  average_ip_count: Optional[float]
  average_ns_count: Optional[float]
  average_tls_chain_length: Optional[float]
  average_tls_cert_validity: Optional[float]
  average_nerd_score: Optional[float]
  lex_averages: Dict[lex_features, float]


def entropy(string):
  counts = Counter(string)
  frequencies = ((i / len(string)) for i in counts.values())
  return - sum(f * math.log(f, 2) for f in frequencies)


def get_stats(collections = ['blacklisted', 'benign']):
  all_stats: Dict[str, Optional[Stats]] = dict.fromkeys(collections, None) #type: ignore - will definitely be Stats or None
  mongo = MongoWrapper('blacklisted')
  for collection in collections:
    mongo.switch_collection(collection)
    cursor, count = mongo.get_resolved()
    #
    stats = Stats(collection=collection, total=count, missing={}, txt_verification_present_count=0, txt_verifications={}, rdap_last_change_median=0, most_common_tlds=[], most_common_registrars=[], most_common_countries=[], most_common_tls_authorities=[], average_ip_count=None, average_ns_count=None, average_tls_chain_length=None, average_tls_cert_validity=None, average_nerd_score=None, lex_averages={})
    rdap_last_changes = []
    tlds = []
    registrars = []
    countries = []
    tls_authorities = []
    ip_counts = []
    ns_counts = []
    tls_chain_lengths = []
    tls_cert_validities = []
    nerd_scores = []
    entropies = []
    number_counts = []
    domain_levels = []
    #
    for data in cursor:
      # missing data and DNS counts
      if data['dns'] is None:
        if data['remarks']['dns_evaluated_on'] is not None:
          stats['missing']['dns'] = stats['missing'].get('dns', 0) + 1
      else:
        if data['dns']['MX'] and len(data['dns']['MX']) == 0:
          stats['missing']['dns.mx'] = stats['missing'].get('dns.mx', 0) + 1
        if data['dns']['A']:
          if len(data['dns']['A']) == 0:
            stats['missing']['dns.a'] = stats['missing'].get('dns.a', 0) + 1
          else:
            ip_counts.append(len(data['dns']['A']))
        if data['dns']['NS'] and len(data['dns']['NS']) > 0:
          ns_counts.append(len(data['dns']['NS']))
      if data['rdap'] is None:
        if data['remarks']['rdap_evaluated_on'] is not None:
          stats['missing']['rdap'] = stats['missing'].get('rdap', 0) + 1
      if data['tls'] is None:
        if data['remarks']['tls_evaluated_on'] is not None:
          stats['missing']['tls'] = stats['missing'].get('tls', 0) + 1
      if data['ip_data'] is None:
        stats['missing']['ip_data'] = stats['missing'].get('ip_data', 0) + 1
      else:
        for ip in data['ip_data']:
          if ip['geo'] is None and ip['remarks']['geo_evaluated_on'] is not None:
            stats['missing']['ip_data.geo'] = stats['missing'].get('ip_data.geo', 0) + 1
          if ip['rdap'] is None and ip['remarks']['rdap_evaluated_on'] is not None:
            stats['missing']['ip_data.rdap'] = stats['missing'].get('ip_data.rdap', 0) + 1
      # txt verification
      if data['dns'] and data['dns']['TXT'] and len(data['dns']['TXT']) > 0:
        found_any = False
        # look for known verification strings in DNS TXT records
        for txt in data['dns']['TXT']:
          for verification in txt_verified_strings:
            if verification in txt:
              found_any = True
              stats['txt_verifications'][verification] = stats['txt_verifications'].get(verification, 0) + 1
        if found_any:
          stats['txt_verification_present_count'] += 1
      # rdap last change
      if data['rdap'] and data['rdap']['last_changed_date']:
        last_change = data['rdap']['last_changed_date']
        seconds_since_last_change = (datetime.now() - last_change).total_seconds()
        rdap_last_changes.append(seconds_since_last_change)
      # tlds
      tld = data['domain_name'].split('.')[-1]
      tlds.append(tld)
      # registrars
      if data['rdap'] and 'registrar' in data['rdap']['entities']:
        entities_with_names = filter(lambda x: 'name' in x, data['rdap']['entities']['registrar'])
        names = map(lambda x: x['name'], entities_with_names) #type: ignore - filtered out entities without names
        registrars.extend(names)
      # countries and nerd
      if data['ip_data']:
        for ip in data['ip_data']:
          if ip['geo'] and ip['geo']['country']:
            countries.append(ip['geo']['country'])
          if ip['rep'] and ip['rep']['nerd']:
            nerd_scores.append(ip['rep']['nerd']['rep'])
      # tls stuff
      if data['tls']:
        tls_chain_lengths.append(len(data['tls']['certificates']))
        #for cert in data['tls']['certificates']:
        cert = data['tls']['certificates'][0]
        if not cert['is_root']:
          if cert['organization']:
            tls_authorities.append(cert['organization'])
          if cert['valid_len']:
            tls_cert_validities.append(cert['valid_len'])
      # entropy
      entropies.append(entropy(data['domain_name']))
      # number counts
      number_counts.append(len(re.findall(r'\d', data['domain_name'])))
      # domain levels
      domain_levels.append(len(data['domain_name'].split('.')))
    # end for
    #
    # do statistics
    # rdap last change
    if len(rdap_last_changes) > 0:
      stats['rdap_last_change_median'] = median(rdap_last_changes)
    # tlds
    stats['most_common_tlds'] = Counter(tlds).most_common(5)
    # registrars
    stats['most_common_registrars'] = Counter(registrars).most_common(5)
    # countries
    stats['most_common_countries'] = Counter(countries).most_common(5)
    # tls authorities
    stats['most_common_tls_authorities'] = Counter(tls_authorities).most_common(5)
    # ip counts
    if len(ip_counts) > 0:
      stats['average_ip_count'] = mean(ip_counts)
    # ns counts
    if len(ns_counts) > 0:
      stats['average_ns_count'] = mean(ns_counts)
    # tls chain lengths
    if len(tls_chain_lengths) > 0:
      stats['average_tls_chain_length'] = mean(tls_chain_lengths)
    # tls cert validities
    if len(tls_cert_validities) > 0:
      stats['average_tls_cert_validity'] = mean(tls_cert_validities)
    # nerd scores
    if len(nerd_scores) > 0:
      stats['average_nerd_score'] = mean(nerd_scores)
    # entropies
    if len(entropies) > 0:
      stats['lex_averages']['entropy'] = mean(entropies)
    # number counts
    if len(number_counts) > 0:
      stats['lex_averages']['number_count'] = mean(number_counts)
    # domain levels
    if len(domain_levels) > 0:
      stats['lex_averages']['domain_levels'] = mean(domain_levels)
    #
    all_stats[collection] = stats
  return all_stats

def write_stats(stats):
  with open('stats.json', 'w') as f:
    json.dump(stats, f, indent=2)

def print_stats(stats):
  for collection, stats in stats.items():
    print('Collection:', collection)
    print('  total accounted for: {}'.format(stats['total']))
    print('  missing data')
    for key, value in stats['missing'].items():
      print('    {}: {}'.format(key, value))
    print('  txt verifications')
    for key, value in stats['txt_verifications'].items():
      print('    {}: {}'.format(key, value))
    print('  had any txt verification at all: {}'.format(stats['txt_verification_present_count']))
    print('  rdap last change median: {}'.format(stats['rdap_last_change_median']))
    print('  most common tlds: {}'.format(stats['most_common_tlds']))
    print('  most common registrars: {}'.format(stats['most_common_registrars']))
    print('  most common countries: {}'.format(stats['most_common_countries']))
    print('  most common tls authorities: {}'.format(stats['most_common_tls_authorities']))
    print('  average ip count: {}'.format(stats['average_ip_count']))
    print('  average ns count: {}'.format(stats['average_ns_count']))
    print('  average tls chain length: {}'.format(stats['average_tls_chain_length']))
    print('  average tls cert validity: {}'.format(stats['average_tls_cert_validity']))
    print('  average nerd score: {}'.format(stats['average_nerd_score']))
    print('  lex analysis averages')
    for key, value in stats['lex_averages'].items():
      print('    {}: {}'.format(key, value))
    print('-'*80)


def write_coords(collection):
  mongo = MongoWrapper(collection)
  cursor, _ = mongo.get_resolved()
  coords = []
  for data in cursor:
    if data['ip_data']:
      for ip in data['ip_data']:
        if ip['geo'] and ip['geo']['latitude'] and ip['geo']['longitude']:
          coords.append(f'{ip["geo"]["longitude"]},{ip["geo"]["latitude"]}')
  with open('coords_{}.csv'.format(collection), 'w') as f:
    f.write('\n'.join(coords))