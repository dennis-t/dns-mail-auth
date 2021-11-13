#!/usr/bin/env python3

import requests
import lxml.html
import re
from bs4 import BeautifulSoup
import time
import os
import logging
import hashlib
from multiprocessing import Process
import dnsrecords
import mysql.connector as mc
import datetime
import dns.resolver
import dnsrecords
import crawling_functions as crawling


def request_website(url):
    try:
        page = requests.get(url)
    except Exception as e:
        logging.error("Request failed:" + str(e))
        raise
    return page


def fetch_mails(url, year, month):

    website = "https://lkml.org/"

    page = request_website(url)
    tree = lxml.html.fromstring(page.content)
    monthly_mails = tree.xpath("/html/body/table/tr[2]/td[3]/table/tr/td[1]/a/@href")

    for day in monthly_mails:
        page_day = request_website(website + day)

        tree = lxml.html.fromstring(page_day.content)
        daily_mails = tree.xpath("/html/body/table/tr[2]/td[3]/table/tr/td[2]/a/@href")

        for mail in daily_mails:

            # Requesting mails with headers
            mail = mail.replace('/lkml', 'lkml/mheaders')
            html_mail = request_website(website + mail)

            day = day.split("/")[-1:][0]

            cur_dir = os.path.join("mail-results", year, str(month), str(day))

            crawling.create_dir(cur_dir)
            crawling.save_results(cur_dir, "mail", html_mail.text)


def parse_dkim(directory, mail_name, result_dir, db):

        cursor = db.cursor()

        mail_path = os.path.join(directory, mail_name)
        mail_content = open(mail_path, 'r')

        mail_content = mail_content.read()

        regex = r"DKIM-Signature.{,30}?v=1;.{,50}?((?=(s=\S+);).{,20}?(?=(d=\S+);)|(?=(d=\S+);).{,20}?(?=(s=\S+);))"
        html_soup = BeautifulSoup(mail_content, "lxml")
        html_str = str(html_soup.text.encode('utf-8'))
        matches = re.finditer(regex, html_str, re.IGNORECASE | re.DOTALL)

        for match in matches:
            domain = ""
            selektor = ""

            for groupNum in range(2, len(match.groups()) + 1):
                if match.group(groupNum):
                    attr, value = match.group(groupNum).split('=')
                    if attr == "d":
                        domain = value
                    elif attr == "s":
                        selektor = value
            if domain == "" or selektor == "":
                break

            existing_selektor = ""
            #existing_selektor = check_duplicates(cursor, domain, selektor)

            if not existing_selektor:
                dkim_dns = selektor + "._domainkey." + domain

                # Crawling for DKIM Records
                try:
                    dkim_record = resolver.query(dkim_dns, 'TXT')
                except dns.exception.DNSException:
                    dkim_record = ""
                else:
                    dkim_record = crawling.filter_record(dkim_record, "p=", domain)
                    logging.info("Domain:" + dkim_record)

                    if dkim_record:
                        cur_dir = os.path.join(result_dir, domain)
                        crawling.create_dir(cur_dir)

                        dkim = dnsrecords.DkimRecord(domain, dkim_record, selektor)

                        logging.info("DKIM Record domain {} key {}".format(dkim.domain, dkim.public_key))

                        # Check if key exists for this DKIM record
                        if dkim.public_key != "Key is revoked":

                            dkim.save_key(cur_dir, dkim_dns, dkim.public_key)
                            dkim.set_keylength(cur_dir, dkim_dns)

                        sql = 'INSERT INTO dkim_records (domain, selektor, dkim_record, dkim_key_length, crawling_date) VALUES  (%s, %s, %s, %s, %s)'
                        try:
                            cursor.execute(sql, (domain, selektor, dkim.public_key, dkim.key_length, crawling_date))
                            db.commit()
                        except Exception as e:
                            logging.error("Failed to execute SQL statement:" + str(e))


def check_duplicates(db, domain, selektor):

    sql = "SELECT id FROM dkim_records WHERE domain=%s and selektor=%s"

    db.execute(sql, (domain, selektor))
    results = db.fetchall()

    return results


def evaluate_mails(directory, result_dir):

    local_time = datetime.datetime.now()
    local_time = local_time.strftime("%Y-%m-%d")

    db = crawling.connect_database()
    for root, dirs, files in os.walk(directory):
        for mail in files:
            if mail:
                parse_dkim(root, mail, result_dir, db)


if __name__ == '__main__':

    logging.basicConfig(filename="crawling_mail.log", level=logging.INFO,
                        format="%(asctime)s:%(levelname)s:%(message)s")

    cur_time = datetime.datetime.now()
    crawling_date = cur_time.strftime("%Y-%m-%d")

    crawling.create_dir("mail-results")

    kernel_url = "https://lkml.org/lkml"
    years = [2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 0.5
    resolver.lifetime = 0.5

    for year in years:
        for month in range(1, 13):
            url = kernel_url + "/" + str(year) + "/" + str(month)
            print(url)
            p = Process(target=fetch_mails, args=(url, str(year), str(month)))
            p.start()
    evaluate_mails("mail-results", "results-dkim")
