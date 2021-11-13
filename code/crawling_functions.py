
import os
import mysql.connector as mc
import hashlib
from multiprocessing import Process
import logging


def create_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def save_results(directory, record_type, dns_record):
    """ Store the value of dns_record in a file with
        the md5 value as the filename"""

    record_hash = hashlib.md5()
    record_hash.update(dns_record.encode())
    record_hash = record_hash.hexdigest()

    files = os.listdir(directory)
    check_duplicate = [file for file in files if file == record_hash]

    if not check_duplicate:
        filename = "{}-{}".format(record_hash, record_type)
        filepath = os.path.join(directory, filename)
        try:
            result = open(filepath, "w")
            result.write(dns_record)
            result.close()
        except OSError:
            logging.error("Failed to save file {}".format(filepath))


def filter_record(dns_records, dns_type, domain):
    """ Filter dns_type records (e.g SPF, DKIM, DMARC) from all the TXT records"""

    filtered_records = list()

    for dns_record in dns_records:
        txt_record = ""

        try:
            for parts in dns_record.strings:
                parts = parts.decode('utf-8', errors='replace')
                txt_record += parts
        except Exception as e:
            txt_record = ""
            logging.warning("Not valid DNS {} format for {} {}".format(dns_type, dns_record, domain))
            logging.error("Failed to decode Record {} error {}".format(dns_record.strings, str(e)))

        if dns_type in txt_record:
            filtered_records.append(txt_record)

    return filtered_records


def read_record(directory, file):

    filepath = os.path.join(directory, file)
    try:
        fp = open(filepath, 'r')
        dns_record = fp.read()
    except Exception as e:
        dns_record = ""
        logging.error("Exception: {}".format(str(e)))
        logging.error("Failed to read file {}".format(filepath))

    return dns_record


def connect_database():
    try:
        connection = mc.connect(host='127.0.0.1', user='dns_crawler', passwd='ma4dns-email', db='dns')
    except mc.Error as e:
        logging.error("Cannot connect to db: %s", e)
        raise

    return connection


