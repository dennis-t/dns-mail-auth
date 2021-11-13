import dns.resolver
import os
import logging
import datetime
from multiprocessing import Process, Pool
from itertools import product
import re
import pandas
import datetime
import tarfile
import dnsrecords
import shutil
import crawling_functions as crawler


def query_records(cur_dir, domain_part):
    for domain in domain_part:

        domain_dir = os.path.join(cur_dir, domain)

        crawler.create_dir(domain_dir)

        # Crawling for SPF Records
        try:
            spf_records = resolver.query(domain, 'SPF')
        except dns.exception.DNSException:
            spf_records = ""
        except Exception as e:
            spf_records = ""
            logging.error("Exception for domain {} : {}".format(spf_records, str(e)))
        else:
            spf_records = crawler.filter_record(spf_records, "v=spf1", domain)

        if spf_records:
            for spf_record in spf_records:
                crawler.save_results(domain_dir, "spf_record", spf_record)

        # Crawling for SPF Records
        try:
            txt_records = resolver.query(domain, 'TXT')
        except dns.exception.DNSException as e:
            txt_records = ""
            logging.error("Exception SPF domain {} : {}".format(domain, str(e)))
        except Exception as e:
            txt_records = ""
            logging.error("Exception for domain {} : {}".format(txt_records, str(e)))
        else:
            txt_records = crawler.filter_record(txt_records, "v=spf1", domain)

        if txt_records:
            for txt_record in txt_records:
                crawler.save_results(domain_dir, "spf_record", txt_record)

        # Crawling for DMARC Records
        try:
            dmarc_domain = "_dmarc." + domain
            dmarc_records = resolver.query(dmarc_domain, 'TXT')
        except dns.exception.DNSException as e:
            dmarc_records = ""
            logging.error("Exception DMARC domain {}: {}".format(domain, str(e)))
        except Exception as e:
            dmarc_records = ""
            logging.error("Exception for domain {} : {}".format(dmarc_domain, str(e)))
        else:
            dmarc_records = crawler.filter_record(dmarc_records, "v=DMARC1", domain)

        if dmarc_records:
            for dmarc_record in dmarc_records:
                crawler.save_results(domain_dir, "dmarc_record", dmarc_record)

        # Crawling for MTA-STS Records
        try:
            mta_domain = "_mta-sts." + domain
            mta_records = resolver.query(mta_domain, 'TXT')
        except dns.exception.DNSException:
            mta_records = ""
        except Exception as e:
            mta_records = ""
            logging.error("Exception for domain {} : {}".format(mta_domain, str(e)))
        else:
            mta_records = crawler.filter_record(mta_records, "v=STSv1", domain)

        if mta_records:
            for mta_record in mta_records:
                crawler.save_results(domain_dir, "mta_record", mta_record)


def parse_dmarc(directory, files, domain, db, time):

    cursor = db.cursor()
    sql = 'INSERT INTO dmarc_records (valid, dmarc_policy, domain, domain_list, crawling_date) VALUES (%s, %s, %s, %s, %s)'

    file = files[0]

    dmarc_record = crawler.read_record(directory, file)
    dmarc = dnsrecords.DmarcRecord(domain, dmarc_record)

    try:
        cursor.execute(sql, (dmarc.valid, dmarc.dmarc_policy, dmarc.domain, "Tranco", time))
        db.commit()
    except Exception as e:
        logging.error("Failed to execute SQL statement:" + str(e))
        logging.error("SQL statements {} ".format(domain))


def parse_mta(directory, files, domain, db, time):

    for file in files:
        mta_record = crawler.read_record(directory, file)
        cursor = db.cursor()

        mta = dnsrecords.MtaRecord(domain, mta_record)
        mta.query_policy()
        mx = ','.join(mta.mx)

        sql = 'INSERT INTO mta_records (domain, policy_mode, mx, max_age, domain_list, crawling_date) VALUES (%s, %s, %s, %s, %s, %s)'

        try:
            cursor.execute(sql, (mta.domain, mta.policy_mode, mx, mta.max_age, "Tranco", time))
            db.commit()
        except Exception as e:
            logging.error("Failed to execute SQL statement: {} error: {}".format(sql, str(e)))
            logging.error(" domain {} policy: {} , mx {}".format(domain, mta.policy_mode, mx))


def parse_spf(directory, files, domain, db, time):

    valid = False
    result_description = ""

    cursor = db.cursor()
    sql = 'INSERT INTO spf_records (domain, spf_policy, valid, result_description, domain_list, crawling_date) VALUES (%s, %s, %s, %s, %s, %s)'

    for file in files:

        spf_record = crawler.read_record(directory, file)
        spf = dnsrecords.SpfRecord(domain, spf_record)
        spf.query_recursive(spf_record, domain)
        spf.request_records()

        result_description = spf.result_description

        # Valid SPF Record
        if spf.valid == 1:

            valid = True

            try:
                cursor.execute(sql, (domain, spf.spf_policy, spf.valid, spf.result_description, "Tranco", time))
                domain_id = cursor.lastrowid
                db.commit()
            except Exception as e:
                domain_id = ""
                logging.error("Failed to execute SQL statement:" + sql + str(e))
                logging.error(" domain {} policy: {} , time {}".format(domain, spf.spf_policy, time))

            if domain_id:

                sql2 = 'INSERT INTO spf_includes (domain_id, domain, include_record, ancestor_record, crawling_date) VALUES (%s, %s, %s, %s, %s)'
                for n in range(len(spf.include_chain)):
                    if spf.include_chain[n]:
                        ancestor_record = spf.include_chain[n][0]
                        spf_include = spf.include_chain[n][1]
                    else:
                        ancestor_record = ""
                        spf_include = ""
                    try:
                        cursor.execute(sql2, (int(domain_id), domain, spf_include, ancestor_record, time))
                        db.commit()
                    except Exception as e:
                        logging.error("Failed to execute SQL :" + sql2 + str(e))
                        logging.error("SQL Statement  domain_id {} include {} domain {}".format(domain_id, spf_include, domain))

                sql_ips = 'INSERT INTO spf_authorized_ips (domain_id, ip_address, crawling_date) VALUES (%s, %s, %s)'
                sql_values = [(int(domain_id), authorized_ip, time) for authorized_ip in spf.authorized_ips]
                try:
                    cursor.executemany(sql_ips, sql_values)
                    db.commit()
                except Exception as e:
                    logging.error("Failed to execute SQL :" + sql_ips + str(e))
                    logging.error("SQL Statement ips {} include {} domain {}".format(domain_id, spf.authorized_ips, domain))
                break

    # Invalid SPF Record
    if valid == False:
        cursor.execute(sql, (domain, "none", 0, result_description, "Tranco", time))
        db.commit()


def evaluate_records(cur_dir, dir_part):
    # Connect to database
    db = crawler.connect_database()
    eval_date = cur_dir.split('/')[2]
    for directory in dir_part:
        directory = os.path.join(cur_dir, directory)
        try:
            domain = directory.split("/")[3]
            files = os.listdir(directory)

            spf_files = [file for file in files if file.endswith("spf_record")]

            dmarc_files = [file for file in files if file.endswith("dmarc_record")]

            mta_files = [file for file in files if file.endswith("mta_record")]

            if spf_files:
                parse_spf(directory, spf_files, domain, db, eval_date)
            if dmarc_files:
                parse_dmarc(directory, dmarc_files, domain, db, eval_date)
            if mta_files:
                parse_mta(directory, mta_files, domain, db, eval_date)

        except Exception as e:
            logging.error("Exception  {} domain {} directory {}".format(str(e), domain, directory))
    db.close()


def multi_thread_validation(current_dir, function, domain_list, thread=80):
    """
    use of multiple threads to perform the validation process faster
    """

    index1 = 0
    index2 = 0

    if len(domain_list) < thread:
        thread = len(domain_list)

    # divide ip_set to blocks for later multiprocess.
    try:
        slice_len = len(domain_list) // thread
    except:
        slice_len = 1
    jobs = []

    for i in range(thread - 1):
        if i == 0:
            index1 = i
            index2 = i
        index2 += slice_len

        part = domain_list[index1:index2]
        p = Process(target=function, args=(current_dir, part))
        jobs.append(p)
        p.start()
        index1 += slice_len

    part = domain_list[index1:]

    p = Process(target=function, args=(current_dir, part))
    jobs.append(p)
    p.start()

    # join threads
    for job in jobs:
        if job.is_alive():
            job.join()


if __name__ == '__main__':
    logging.basicConfig(filename="crawling_tranco.log", level=logging.INFO,
                        format="%(asctime)s:%(levelname)s:%(message)s")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    crawler.create_dir("../results")

    cur_time = datetime.datetime.now()
    crawling_date = cur_time.strftime("%Y-%m-%d")

    cur_dir = os.path.join("../results", crawling_date)
    crawler.create_dir(cur_dir)

    data = pandas.read_csv("tranco-list.csv")

    domain_list = data['Domain']

    logging.info("Crawling starting")

    request_func = locals()['query_records']
    multi_thread_validation(cur_dir, request_func, domain_list)

    dir_list = os.listdir(cur_dir)

    eval_func = locals()['evaluate_records']
    multi_thread_validation(cur_dir, eval_func, dir_list)

    logging.info("Crawling finished")

    # Create .tar.gz Archive
    archive_name = os.path.join('../results/' , 'tranco_' + crawling_date + '.tar.gz')

    tf = tarfile.open(archive_name, mode='w:gz')

    tf.add(cur_dir, recursive=True)
    tf.close()

    # Remove results
    shutil.rmtree(cur_dir)

