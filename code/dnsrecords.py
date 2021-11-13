#!/usr/bin/python

import re
import dns.resolver
import requests
import os
from Crypto.PublicKey import RSA
import logging
import crawling_functions as crawling
import spf


class DomainRecord:
    def __init__(self, domain, txt_record):
        self.domain = domain
        self.txt_record = txt_record


class DkimRecord(DomainRecord):
    """ Class for DKIM Records """

    def __init__(self, domain, txt_record, selektor):
        super().__init__(domain, txt_record)
        self.selektor = selektor
        self.__set_publickey__()
        self.key_length = 0

    def __set_publickey__(self):

        # Search for public DKIM key
        regex = r"\W+p=([a-zA-Z0-9\/+-]*)"
        try:
            self.public_key = re.findall(regex, self.txt_record)[0]
        except:
            self.public_key = "None"
            logging.error("Failed to find Key {}".format(self.domain, self.txt_record))
        if self.public_key == "":
            self.public_key = "Key is revoked"

    def set_keylength(self, file):

        try:
            key = open(file, "r")
        except IOError:
            self.key_length = 0
        # Load the public key to get key length
        try:
            public_key = RSA.importKey(key.read())
            self.key_length = public_key.n.bit_length()
        except Exception as e:
            self.key_length = 0
            self.public_key = "Invalid Key"
            logging.error("Failed to load key {}: ".format(file, e))

    @staticmethod
    def save_key(directory, filename, key):

        filename = filename + ".pem"

        files = os.listdir(directory)
        check_duplicate = [file for file in files if file == filename]

        if not check_duplicate:
            filename = os.path.join(directory, filename)
            dkim_key = open(filename, "w")
            dkim_key.write("-----BEGIN PUBLIC KEY-----\n")
            dkim_key.write(key)
            dkim_key.write("\n-----END PUBLIC KEY-----")
            dkim_key.close()


class MtaRecord(DomainRecord):
    """ Class for MTA-STS Records """

    def __init__(self, domain, txt_record):
        super().__init__(domain, txt_record)
        self.__set_MtaId__()
        self.version = ""
        self.policy_mode = ""
        self.mx = list()
        self.max_age = 0

    def __set_MtaId__(self):
        regex = r"\W+p=(.+);"
        try:
            mta_id = re.findall(regex, self.txt_record)[0]
        except:
            mta_id = ""
        self.mta_id = mta_id

        self.key_length = ""

    def query_policy(self):

        url = "https://mta-sts.{domain}/.well-known/mta-sts.txt".format(domain=self.domain)
        try:
            webpage = requests.get(url, timeout=10)
        except requests.ConnectionError:
            lines = ""
            logging.error("Failed to request {} ".format(url))
        else:
            lines = webpage.text.replace('\r', '')
            lines = lines.split('\n')

            # Filter empty elements from lines
            lines = filter(None, lines)

            for line in lines:

                setting, value = str(line).split(':')
                if setting == "version":
                    self.version = value
                elif setting == "mode":
                    self.policy_mode = value
                elif setting == "mx":
                    value = value.strip('\r')
                    self.mx.append(value)
                elif setting == "max_age":
                    self.max_age = int(value)


class DmarcRecord(DomainRecord):
    """ Class for DMARC Records """

    def __init__(self, domain, txt_record):
        super().__init__(domain, txt_record)
        self.dmarc_policy = ""
        self.valid = 1
        self.__set_dmarcpolicy()

    def __set_dmarcpolicy(self):
        # Parse for dmarc policy

        regex = r"\W+p=(\w+)"
        try:
            dmarc_policy = re.findall(regex, self.txt_record)[0]
        except:
            self.valid = 0
            dmarc_policy = ""
        if dmarc_policy == "none" or dmarc_policy == "reject" or dmarc_policy == "quarantine":
            self.dmarc_policy = dmarc_policy
        else:
            self.valid = 0
            self.dmarc_policy = ""

        # check if DMARC1 is the first element of the record
        regex2 = r"[\w=]+\s*;\s*[\w=]+"
        match = re.match(regex2, self.txt_record)

        if match:
            lspf = self.txt_record.split(';')
            line = [s.rstrip('" ') for s in lspf]
            if line[0] != "v=DMARC1":
                self.valid = 0
                logging.error("DMARC Record invalid: {} domain {}".format(self.txt_record, self.domain))
        else:
            self.valid = 0
            logging.error("DMARC Record invalid: {} domain {}".format(self.txt_record, self.domain))


class SpfRecord(DomainRecord):
    """ Class for SPF Records """

    def __init__(self, domain, txt_record):
        super().__init__(domain, txt_record)
        self.valid = 1
        self.result_description = ""
        self.set_validity(self.domain)
        self.authorized_ips = set()
        self.dns_lookups = list()
        self.spf_includes = list()
        self.include_chain = list()
        self.set_policy(self.txt_record)

    def set_validity(self, domain):

        sender = "test@" + domain
        try:
            valid = spf.check2(i='1.1.1.1', h='mx.test', s=sender)
        except Exception as e:
            valid = "error"
            logging.error("Failed to validate SPF record {} : {}".format(self.domain, str(e)))
        if "permerror" in valid[0]:
            self.valid = 0
            self.result_description = valid[1]
        else:
            self.valid = 1

    def set_policy(self, record):

        index = record.find("all")
        if record[index - 1] == "+" or record[index - 1] == "-" or \
                record[index - 1] == "~" or record[index - 1] == "?":
            self.spf_policy = record[index - 1]
        else:
            self.spf_policy = "?"

    def query_recursive(self, records, domain, rtype=None):
        """
        Recursive fetching of all the elements which are listed in the
        spf record
        """

        lspf = re.split('\s', str(records))
        line = [s.strip('"') for s in lspf]
        # Loop to look at all elements of the returned record

        for element in line:
            # Add includes to lookup for further processing and increment counter
            if line[0] != 'v=spf1' and rtype != "A" and rtype != "MX":
                break
            if "include:" in element:
                try:
                    inc = element.split(":")
                    match = re.match(r'[\w-]+\.\w+', inc[1], re.IGNORECASE)
                    # Check if include contains valid domain name
                    if match:
                        # Check if include is not already added
                        if inc[1] not in self.spf_includes:
                            self.spf_includes.append(inc[1])
                            self.dns_lookups.append((inc[1], domain, 'Include', 'TXT'))
                except:
                    logging.error("Failed to index redirect: {} record {}".format(redirect, element))
            elif "redirect=" in element and element not in self.spf_includes:
                try:
                    redirect = element.split("=")
                    if redirect[1] not in self.spf_includes:
                        self.spf_includes.append(redirect[1])
                        self.dns_lookups.append((redirect[1], domain, "Redirect", "TXT"))
                except:
                    logging.error("Failed to index redirect: {} record {}".format(redirect, element))
            elif "mx:" in element:
                mx = element.split(':')
                # check if mx contains subnet (mx:test.de/24)
                if "/" in mx[1]:
                    mx_name, subnet = mx[1].split('/')
                    self.dns_lookups.append((mx_name, domain, subnet, "MX"))
                else:
                    self.dns_lookups.append((mx[1], domain, "None", "MX"))
            elif "a:" in element.lower() and "ip6" not in element.lower():
                a = element.split(":")
                self.dns_lookups.append((a[1], domain, "None", "A"))
            elif element.lower() == "mx" or element.lower() == "+mx":
                self.dns_lookups.append((self.domain, domain, "None", "MX"))
            elif element.lower() == "a" or element.lower() == "+a":
                self.dns_lookups.append((self.domain, domain, "None", "A"))

            # Print the IPv4 addresses in an easily copiable block
            elif "ip4:" in element.lower():
                ip = element.split(":")
                if "/" not in ip[1]:
                    self.authorized_ips.add(ip[1] + "/32")
                else:
                    self.authorized_ips.add(ip[1])
            elif "ip6:" in element.lower():
                ip6 = element
                self.authorized_ips.add(ip6[4:])
            elif rtype == "A":
                self.authorized_ips.add(element)
            elif rtype == "MX" and len(element) > 3:
                self.dns_lookups.append(element, domain, "None", "A")


    def check_ipv4(self, ip):
        """
        Check if ip address contains a subnet e.g /24, if not
        it is a single ip with /32
        """

        if "/" not in ip:
            authorized_ips.add(ip + "/32")
        else:
            authorized_ips.add(ip)

    def request_records(self):
        """
        Perform a DNS lookup to a specified domain and a
        chosen record type
        """

        resolver = dns.resolver.Resolver()
        resolver.timeout = 0.3
        resolver.lifetime = 0.3

        for lookup in self.dns_lookups:
            domain, ancestor, record_option, record_type = lookup
            # DNS query and print domain name being processed while handling any error exceptions
            try:
                answers = resolver.query(domain, record_type)
            except dns.resolver.NXDOMAIN:
                answers = ""
            except dns.resolver.NoAnswer:
                answers = ""
            except dns.resolver.NoNameservers:
                answers = ""
            except dns.exception.Timeout:
                answers = ""
            except dns.name.LabelTooLong:
                answers = ""
            except:
                answers = ""

            if record_type == "TXT":
                answer = crawling.filter_record(answers, "v=spf1", self.domain)
                if answer:
                    if record_option == "Redirect":
                        self.set_policy(answer[0])
                    self.include_chain.append((ancestor, domain))
                    self.query_recursive(answer[0], domain, record_type)
            for answer in answers:
                if record_type == "MX":
                    mailserver = answer.to_text().split()[1]
                    if "/" in record_option:
                        self.dns_lookups.append((mailserver, domain, subnet, "A"))
                    else:
                        self.dns_lookups.append((mailserver, domain, "None", "A"))
                elif record_type == "A":
                    ip = answer.to_text()
                    if "/" not in ip:
                        self.authorized_ips.add(ip + "/32")
                    elif record_option != "None":
                        self.authorized_ips.add(ip + "/" + subnet)
                    else:
                        self.authorized_ips.add(ip)
