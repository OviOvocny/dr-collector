

#!/usr/bin/env python3

"""SSL.py: First version of SSL loader for SSL model"""
__author__      = "Jan Polisensky"

from distutils import extension
from xml import dom

import socket
import concurrent.futures

import OpenSSL
import datetime




class SSL:

    def __init__(self) -> None:
        """
        ! Constructor of the SSL resolver
        """

        super().__init__()
        self.name = "ssl"
        self.timeout = 10 # Default timeout
        self.status = None
        self.output = {
            "resolver_name" : self.name,
            "success": None,
            "error_description": None,
            "created": None,
            "data": None
        }


    def __error_message(self, message):

        self.output['success'] = False


        self.output['error_description'] = message

        self.output['created'] = datetime.datetime.now()

        return self.output


    def __get_cert_chain(self, host):
        
        """
        First it test the connection with host on port 443.
        If it timeouts go te next else do handshake and get the cert chain
        """
        global version 

        cont = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        cont.set_timeout(self.timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((host, 443))
            get = str.encode("GET / HTTP/1.1\nUser-Agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36\n\n")
            sock.send(get)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock = OpenSSL.SSL.Connection(context=cont, socket=sock)
            sock.settimeout(self.timeout)
            sock.connect((host, 443))
            sock.setblocking(1)
            sock.set_connect_state()
            sock.set_tlsext_host_name(str.encode(host))
            sock.do_handshake()
            cipher_name = sock.get_cipher_name()
            cert_chain = sock.get_verified_chain()
            chain_len = len(cert_chain)
            version = sock.get_protocol_version_name()
           

        
            
            
        # Error handling somehow #
        
        except socket.gaierror as e:
            return {"error": "Cant resolve domain name or connection error"}

        except socket.timeout as e:
            return {"error": "socket intimeout"}

        except OpenSSL.SSL.Error as e:
            return {"error": "cannot find any root certificates"}

        except ConnectionRefusedError as e:
            return {"error": "connection refused"}

        except OSError as e:
            return {"error": "built-in exception in Python"}



        # Shutdown socket and run away #
        # I want to break freeeeee     #
        try:
            sock.shutdown()
            sock.close()
        except:
            return {"error": "Fatal error during socket closing"}


        return {
                "cipher_name": cipher_name, 
                "cert_chain": cert_chain, 
                "chain_len":chain_len, 
                "TSL_v": version,
                "error": None
               }

    
    def __explore_certs(self, raw_ssl_data):
        """
        Load additional data about ssl certs and save them to json which is returned 
        Structure of input needed by function below...
        {
            "cipher_name": cipher_name, 
            "cert_chain": cert_chain, 
            "chain_len":chain_len, 
            "TSL_v": version,
            "error": None
        }
        """


        
        cert_chain = raw_ssl_data['cert_chain']
        chain_len = raw_ssl_data['chain_len']
        certs = []
        
        for j in range(chain_len):
            
            cert = cert_chain[j]

            # Decoding cert data
            domNotAfter = datetime.datetime.strptime((cert.get_notAfter()).decode("utf-8")[:-1], "%Y%m%d%H%M%S")
            domNotBefore = datetime.datetime.strptime((cert.get_notBefore()).decode("utf-8")[:-1], "%Y%m%d%H%M%S")
            validity_len = domNotAfter - domNotBefore
            attributes = str(cert.get_issuer()).split('/')
            is_root = False        
            
            if j == (chain_len-1):
                is_root = True    

            extension_count = cert.get_extension_count()
            extensions = []
            for i in range (extension_count):
                extensions.append(cert.get_extension(i))
                #print(cert.get_extension(i))
                #print(type(cert))

                # TODO explore extensions and how to use them
                
                
            # decoding all cert properties in chain
            cn = None
            country = None
            organization = None
            for attribute in attributes:
                splited = attribute.split('=')
                
                if splited[0] == 'C':
                    country = splited[1]
                elif splited[0] == 'O':
                    organization = splited[1]
                elif splited [0] == 'CN':
                    cn = splited[1]

            # structure for one cert data 
            # TODO, dig deeper in extension
            cert_attributes = {'organization': organization, 
                'country': country, 
                'common_name': cn, 
                'validity_start': domNotBefore, 
                'validity_end': domNotAfter, 
                'valid_len': validity_len,
                'extension_count': extension_count,
                'is_root': is_root
            }
                
            certs.append(cert_attributes)
        
        features = {
            'cert_count': chain_len,
            'certs_data': certs,
            'cipher_name': raw_ssl_data['cipher_name'],
            'TSL_v': raw_ssl_data['TSL_v'] 
        }
        
        return features
    

    def resolve(self, domain_name, ip_list=[], timeout=10):
        self.timeout = timeout

        if type(domain_name) is not str:
            return self.__error_message("Domain name is not string, got:" + str(type(domain_name)))

        #if ip_list is not []:
        #    print("[Warning]: Ignoring IP list, SSL resolver can work only with domain names")



        raw_data = self.__get_cert_chain(domain_name)

        if raw_data["error"] is not None:
            return self.__error_message("Error during ssl data resolve: " + raw_data["error"])
        
        results = self.__explore_certs(raw_data)
        
        # Return formated data #
        self.output['success'] = True
        self.output['created'] = datetime.datetime.now()
        self.output['data'] = results
        

        return self.output