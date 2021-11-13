import re
import dns.resolver
import os
from multiprocessing import Pool,Value
import multiprocessing
import datetime
import logging
import dnsrecords
import crawling_functions as crawling
import pandas


def init(args):
    """ Initialize the new Process with the global counter """    
    global counter
    counter = args


def query_records(domain):


        global counter
        cname_record = ""
        dkim_duplicate = ""
        
        # Update record counter
        with counter.get_lock():
            counter.value += 1
        if (counter.value % 5000) == 0:
            logging.info("Record nr:" + str(counter.value))

        current_dir = "results-dkim/" + domain

        dictionary = open("dictionary.lst", "r")

        # Check if CNAME exists
        try:
            test_domain = "test._domainkey." + domain
            cname_record = resolver.query(test_domain, 'CNAME')
            cname_record = resolver.query(test_domain, 'TXT')[0]
        except dns.resolver.NoAnswer:
            cname_record = ""
        except dns.exception.DNSException:
            cname_record = ""

        try:
            test_domain2 = "default._domainkey." + domain
            test_record = resolver.query(test_domain, 'TXT')[0]
        except dns.resolver.NoAnswer:
            cname_record = ""
            test_record = "error"
        except dns.exception.DNSException:
            cname_record = ""
            test_record = "error"

        # Domain returns the same record
        if test_record == cname_record:
            logging.info("Duplicated DKIM records - domain {}".format(domain))
        if cname_record:
            try:
                test_domain = "test._domainkey." + domain
                txt_record = resolver.query(test_domain, 'TXT')
            except dns.resolver.NoAnswer:
                txt_record = ""
            except dns.exception.DNSException:
                txt_record = ""
            try:
                txt_record = crawling.filter_record(txt_record, "p=", domain)[0]
            except IndexError:
                txt_record = ""

            if txt_record and "DMARC" not in txt_record:
                crawling.create_dir(current_dir)
                logging.info("Valid Record for {}: {}".format(test_domain, txt_record))
                parse_dkim(current_dir, domain, "test", txt_record, crawling_date)
                crawling.save_results(current_dir, "dkim_record", txt_record)

        # If no CNAME exists iterate over the whole dictionary
        else:
            for selektor in dictionary:
                selektor = selektor.strip("\n")

                dkim_record = selektor + "._domainkey." + domain
                # Crawling for DKIM Records
                try:
                    txt_record = resolver.query(dkim_record, 'TXT')
                except dns.exception.DNSException:
                    txt_record = ""
                if txt_record:
                    crawling.create_dir(current_dir)

                    # Get all possible DKIM records for that selektor and domain
                    try:
                        txt_records = crawling.filter_record(txt_record, "p=", domain)
                    except IndexError:
                        txt_records = ""
                        logging.error("Index Error for filtering record: {}".format(domain))
                    for txt_record in txt_records:
                        if txt_record and "DMARC" not in txt_record:
                            logging.info("Valid Record for {}: {}".format(dkim_record, txt_record))
                            parse_dkim(current_dir, domain, selektor, txt_record, crawling_date)
                            crawling.save_results(current_dir, "dkim_record", txt_record)


def parse_dkim(directory, domain, selektor, txt_record, time):

    db = crawling.connect_database()

    dkim_record = selektor + "._domainkey." + domain
    dkim = dnsrecords.DkimRecord(domain, txt_record, selektor)

    # Check if key exists for this DKIM record
    if dkim.public_key != "Key is revoked" and dkim.public_key != "None":
        dkim.save_key(directory, dkim_record, dkim.public_key)
        keyfile = os.path.join(directory, dkim_record + ".pem")
        dkim.set_keylength(keyfile)

    sql = 'INSERT INTO dkim_records (domain, selektor, dkim_record, dkim_key_length, crawling_date) VALUES  (%s, %s, %s, %s, %s)'

    try:
        cursor = db.cursor()
        cursor.execute(sql, (dkim.domain, dkim.selektor, dkim.public_key, dkim.key_length, time))
        db.commit()
        db.close()
    except Exception as e:
        logging.error("Failed to execute SQL statement:" + str(e))
        db.close()



if __name__ == '__main__':
    logging.basicConfig(filename="crawling_dkim.log",
                        level=logging.INFO,
                        format="%(asctime)s:%(levelname)s:%(message)s")
    
    counter = Value('i', 0)

    cur_time = datetime.datetime.now()
    crawling_date = cur_time.strftime("%Y-%m-%d")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 0.05
    resolver.lifetime = 0.05

    crawling.create_dir("results-dkim")

    data = pandas.read_csv("alexa_top1M_171103.txt")
    domain_list = data['Domain']

    logging.info("Crawling started")

    p = Pool(initializer=init, initargs =(counter,),processes=350)
    p.map(query_records, domain_list)

    logging.info("Crawling finished")



