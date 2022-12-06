""" File: Data_loader.py
    Author: Jan Polisensky
    ----
    Class and functions for domain data collection
"""


# Import generic modules

import socket
import concurrent.futures
import zipfile
import dns.resolver
import requests
import json
import sys
from pymongo import MongoClient
import pymongo
import urllib.request, urllib.error, urllib.parse
import re
import io
import os
import time
import csv
import whois
from ssl_resolver import SSL

# Import custom modules



#######################
#### resolver setup ###
#######################
forbiddenIps = {"0.0.0.0", "127.0.0.1", "255.255.255.255"} # nonsense IPs, feel free to add more
nonvalidTypes = {}  
validTxtTypes = {"plain", "octet-stream", "html", "csv"} 
validArchTypes = {"x-gzip", "zip"}  
ipRegEx = r"^((?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::)))))|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
ValidHostnameRegex = r"(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]"


######################
##### ip-info API ####
######################

# if not used, limited number of requests
#ip_auth_token="f6157341b9e078"  # medikem token
ip_auth_token="6b3b15bcf578ec"  # seznam token
#ip_auth_token="7b7427498417ed"  # medikem token

########################

class Data_loader:  
    def get_hostnames(self, file_path, position, max=1000):
        with open(file_path, newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
            i = 0
            top_1k = []
            for row in spamreader:
                if i == max:
                    break
                try:
                    top_1k.append(row[position])
                    i=i+1
                except:
                    continue

            return top_1k
    
    # get links from csv
    def get_links(self, file_path):
        links = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as csvf:
            reader = csv.reader(csvf)
            for row in reader:
                links.append(row[1])
            links = links[1:]
            links = [x for x in links if x!='']
            print("Loaded:", len(links), "links")
            return links
    # filter nonsence 
    def clean_links(self, links):
        out_links = []
        for link in links:
            domain = re.search(ValidHostnameRegex, link)
            if domain:

                out_links.append(domain.group(0))

        return out_links
    
    # in: list of blacklists
    # out: domain names
    def get_hostnames_from_links(self, in_data):
        print("Resolving hostnames from blacklists")
        ips = []
        hostnames = []

        for source in in_data:
            tmp = []

            if source.startswith("http"):
                try:
                    retrieved = urllib.request.urlretrieve(source, filename=None)
                except urllib.error.HTTPError as e:
                    print(str(e) + " " + source, file=sys.stderr)
                    input()
                except urllib.error.URLError as e:
                    print(str(e) + " " + source,file=sys.stderr)
                    input()
                # retrieved file
                file_tmp = retrieved[0]

                # file type of retrieved file
                file_info = retrieved[1]

                ctype = file_info.get_content_subtype()
                # print(ctype)

                if ctype in nonvalidTypes:
                    print("Non valid type", ctype)
                    input()

                #print("Reading " + source + " " + ctype)

                #unzip if needed
                if ctype == "zip":
                    with zipfile.ZipFile(file_tmp, 'r') as zip_ref:
                        zip_ref.extractall("tmp")
                    file_tmp = "tmp/" + zip_ref.namelist()[0]
                    ctype = file_tmp.split(".")[-1]

                # urlhaus csv edge case
                if "urlhaus" in source:
                    with open(file_tmp, 'r', encoding='utf-8', errors='ignore') as csvf:
                        reader = csv.reader(csvf)
                        URL_COL = 2 # url column in urlhaus csv
                        for row in reader:
                            if len(row) > URL_COL:
                                domain = re.search(ValidHostnameRegex, row[URL_COL])
                                if domain:
                                    hostnames.append(domain.group(0))
                                    tmp.append(hostnames)

                elif ctype in validTxtTypes:
                    with io.open(file_tmp, "r", encoding="utf-8") as f:
                        for line in f:
                            # All kinds of comments are being used in the sources, they could contain non-malicious domains

                            if len(line) != 0 and  \
                                    not line.startswith("#") and \
                                    not line.startswith(";") and \
                                    not line.startswith("//"):
                                    domain = re.search(ValidHostnameRegex, line)
                                    if domain:
                                        hostnames.append(domain.group(0))
                                        tmp.append(hostnames)
                os.remove(file_tmp)
            print("Loaded:", len(tmp), "from: ", source, 'encoded as: ', ctype)
            input()
        return hostnames

class Base_parser:
    def __init__(self, hostname, resolver_timeout):
        print("[Info]: Starting resolver for:", hostname)
        self.timeout = resolver_timeout
        self.hostname = hostname
        self.dns = None
        self.ip = None
        self.geo_data = None
        self.whois_data = None
        self.ssl_data = None

        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        self.dns_resolver.timeout = resolver_timeout
        self.dns_resolver.lifetime = resolver_timeout

        self.ssl_resolver = SSL()

    def get_dns(self):
        return self.dns

    def get_ip(self):
        return self.ip

    def get_geo_data(self):
        return self.geo_data

    def get_ssl_data(self):
        return self.ssl_data

    def get_whois_data(self):
        return self.whois_data

    def load_whois_data(self):
        whois_record = {}
        try:
            types = ['registrar', 'creation_date', 'expiration_date', 'dnssec', 'emails']
            w = whois.whois(self.hostname)
            i = 0
            for type in types:
                try:
                    whois_record[types[i]] = w[types[i]]
                except:
                    whois_record[types[i]] = None

                i=i+1
            self.whois_data = whois_record
            return True

        except Exception as e:
            #print("[Info]: Resolver can load all whois data")
            return False

    def load_dns_data(self):
        #print("Loading DNS data")
        types = ['A', 'AAAA', 'CNAME', 'SOA', 'NS', 'MX', 'TXT']
        #types = ['TXT']
        dns_records = {}
        i = 0
        for type in types:
            result = None
            try:
                result = self.dns_resolver.resolve(self.hostname, type)
            except Exception as e:
                #print(type + " is not available for this hostname")
                dns_records[types[i]] = None
                i=i+1
                continue

            #print(type + " " + self.hostname + " --> " + str(result[0]))
            #input()
            if type == 'A':
                self.ip = result[0]
            dns_records[types[i]] = str(result[0])
            i=i+1

        self.dns = dns_records

    def load_geo_info(self, ip=None):
        #print("Loading Geo info data")
        if ip is None:
            if self.ip is None:
                #print("Ip of hostname not discovered, doing it manualy...")
                try:
                    self.ip = self.ip_from_host()[self.hostname][0]
                except:
                    print("[Info]: Cant resolve hostname to IP")
                return False
        else:
            self.ip = ip
        
        geo_data = {}
        keys = ['country', 'region' ,'city' ,'loc' ,'org']
        url =  "https://ipinfo.io/" + str(self.ip) + "/?token=" + ip_auth_token
        raw_json = None
        try:
            raw_json = requests.get(url).json()
        except:
            self.geo_data = None
            return
        for i in range(len(keys)):
            try:
                geo_data[keys[i]] = raw_json[keys[i]]
            except:
                geo_data[keys[i]] = None

        self.geo_data = geo_data

    def load_ssl_data(self):
        self.ssl_data = self.ssl_resolver.resolve(self.hostname, self.timeout)

    # Helper, get ip from hostname
    def ip_from_host(self):
        hostname = self.hostname

        ips = []
        domainsIps = {}

        try:
            answer = self.dns_resolver.resolve(hostname)

            for item in answer:
                ips.append(item.to_text())

            domainsIps[hostname] = ips
            return domainsIps

        except Exception as e:
            print(answer)
            print(ips)
  
            print(str(e))
            domainsIps[hostname] = []
            return domainsIps

# fetch all data
def get_data(hostname):
    domain = Base_parser(hostname)
    domain.load_dns_data()
    domain.load_geo_info()
    domain.load_whois_data()
    

    dns_data = domain.get_dns()
    geo_data = domain.get_geo_data()
    whois_data = domain.get_whois_data()
 
    domain_data = {"name": hostname, "dns_data": dns_data, "geo_data": geo_data, "whois_data": whois_data}
    return domain_data







# If script is launched explicitly as main, it can be used to fill database with 
if __name__ == '__main__':

    l = Data_loader()

    raw_blacklisted = l.get_links('./data/Blacklists.csv')

    bad_hostnames = l.get_hostnames_from_links(raw_blacklisted)

    res = Base_parser("google.com", 10)

    res.load_dns_data()
    res.load_geo_info()
    res.load_ssl_data()
    res.load_whois_data()

    print(res.get_dns())
    input()
    print(res.get_whois_data())
    input()
    print(res.get_geo_data())
    input()
    print(res.get_ip())
    input()
    print(res.get_ssl_data())
    





            


