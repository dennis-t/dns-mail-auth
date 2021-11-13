
from py2neo import Graph, Node, Relationship, Transaction
import mysql.connector as mc
import crawling_functions as crawling
from multiprocessing import Process, Pool, Manager, Value
import pyasn
import ipaddress
import geoip2.database
import logging

def create_asn(asn_number, asn_organization):

	tx = graph.begin()

	# Create Node
	as_system = Node("ASN", name=asn_number, organization=asn_organization)

	try:
		tx.create(as_system)
		tx.commit()
	except Exception as e:
		logging.error(str(e))


def create_relation(asn, graph, domain_data):

	db = crawling.connect_database()
	cursor = db.cursor()

	for domain in domain_data:
		# ASn list per domain
		domain_asn = list()
		domain_id = domain[0]
		domain_name = domain[1]
		spf_policy = domain[2]

		try:
			# Create domain node
			domain_node = Node("Domain", name=domain_name, policy=spf_policy)
			tx = graph.begin()
			tx.create(domain_node)
			tx.commit()
		except Exception as e:
			logging.error("Creating Domain" + str(e))

		try:
			sql_ips = "SELECT ip_address from spf_authorized_ips where domain_id={} and ip_address LIKE '%.%.%.%'".format(domain_id)
			cursor.execute(sql_ips)
			ip_addresses = cursor.fetchall()
		except Exception as e:
			ip_addresses = ""

		for ip_address in ip_addresses:
			ip_address = ip_address[0]
			try:
				ip, subnet = ip_address.split('/')
			except Exception as e:
				print(str(e))
				ip = ""
				subnet = ""
			try:
				# Create a ip network and assign it to /24 for ASN lookups
				ipv4_subnet = ipaddress.IPv4Network(ip_address, strict=False)

				# Check if subnet is larger then /24
				ipv4_prefix = int(ipv4_subnet.exploded.split('/')[1])
				if ipv4_prefix < 24:
					ipv4_subnet = list(ipv4_subnet.subnets(new_prefix=24))
					ipv4_subnet = [subnet for subnet in ipv4_subnet if subnet.is_global]
			except:
				ipv4_subnet = ""
				ipv4_prefix = 0

			if ipv4_prefix >= 8:
				for ip in ipv4_subnet:
					ip = ip.exploded.split('/')[0]
					try:
						asn_data = asn.asn(ip)
						asn_number = str(asn_data.autonomous_system_number)
						asn_organization = str(asn_data.autonomous_system_organization)
					except Exception as e:
						asn_number = None
						asn_organization = None

					if asn_number != None:
						# Check if domain has already a connection to this ASN
						if asn_number not in domain_asn:
							# Check if ASN exists
							cypher_asn = 'MATCH (a:ASN {name:"%s", organization:"%s"}) RETURN a' % (asn_number,asn_organization)
							try:
								data = graph.evaluate(cypher_asn)
								if not data:
									create_asn(asn_number, asn_organization)
							except Exception as e:
								logging.error("Exception: Match ASN" + str(e))
							else:
								domain_asn.append(asn_number)
							# Create relation between domain and AS
							cypher = 'MATCH (a:Domain {name:"%s"}),(b:ASN {name:"%s"}) CREATE (a)-[:CONNECTED {ASN:"%s", Domain:"%s"}]->(b) ' % (domain_name, asn_number, domain_name, asn_number)
							try:
								graph.evaluate(cypher)
							except Exception as e:
								logging.error(str(e))
								logging.error("Exception" + str(cypher))
	db.close()



def multi_thread_validation(domains, asn, graph, thread=250):
    """
    use of multiple threads to perform the validation process faster
    """

    index1 = 0
    index2 = 0

    if len(domains) < thread:
        thread = len(domains)

    # divide ip_set to blocks for later multiprocess.
    try:
        slice_len = len(domains) // thread
    except:
        slice_len = 1
    jobs = []

    for i in range(thread - 1):
        if i == 0:
            index1 = i
            index2 = i
        index2 += slice_len

        part = domains[index1:index2]
        p = Process(target=create_relation, args=(asn, graph, part))
        jobs.append(p)
        p.start()
        index1 += slice_len

    part = domains[index1:]

    p = Process(target=create_relation, args=(asn, graph, part))
    jobs.append(p)
    p.start()

    # join threads
    for job in jobs:
        if job.is_alive():
            job.join()



if __name__ == '__main__':

	logging.basicConfig(filename="graph-as.log", level=logging.INFO,
                        format="%(asctime)s:%(levelname)s:%(message)s")	

	crawling_date = "2019-04-13"

	asn = geoip2.database.Reader("GeoLite2-ASN.mmdb")
	graph = Graph("http://localhost:7474/db/", auth=("test","test"))


#	tx = graph.begin()

#	cypher1 = "CREATE CONSTRAINT ON (n:Domain) ASSERT n.name IS UNIQUE"
#	cypher2 = "CREATE CONSTRAINT ON (n:ASN) ASSERT n.name IS UNIQUE"


	db = crawling.connect_database()
	cursor = db.cursor()

#	for limit in range(209999,481959, 60000):

#	for limit in range(0,481959, 60000):
	sql_domains = 'select id,domain, spf_policy from spf_records where crawling_date LIKE "{}" and valid=1'.format(crawling_date)
	try:
		cursor.execute(sql_domains)
		domains = cursor.fetchall()
		multi_thread_validation(domains, asn, graph)
	except Exception as e:
		logging.error("Failed to execute MySQL: {}".format(sql_domains))
		logging.error("Exception: {}".format(str(e)))
	db.close()
