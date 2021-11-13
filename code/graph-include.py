

from py2neo import Graph, Node, Relationship, Transaction
import mysql.connector as mc
import crawling_functions as crawling
from multiprocessing import Process, Pool, Manager, Value



def create_spfnode(include_data):

	try:
		include_record = include_data[0]
		ancestor = include_data[1]
		if include_record not in domain_list:
			tx = graph.begin()
#		print(include_data)
		# Create Node
			includes = Node("SPFInclude2", name=include_record)
			try:
				tx.create(includes)
				tx.commit()
			except Exception as e:
                                if tx.finished == False:
                                    tx.finish()
	except Exception as e:
#		pass
		print("Exception spfnode : {}".format(str(e)))

def create_domainnode(node_data):

	try:
		tx = graph.begin()
		domain_name = node_data[1]
		spf_policy = node_data[2]
		# Create Node
		domain_node = Node("Domain2", name=domain_name, policy=spf_policy)

		try:
			tx.create(domain_node)
			tx.commit()
		except Exception as e:
                        if tx.finished == False:
                            tx.finish()
#			print("Exception {} : domain {}".format(str(e), domain_name))
	except Exception as e:
		print("Exception: {} : domain {}".format(str(e), domain_name))

def create_relation(domain_list, include_list, graph, node_datas):

	try:
		for node_data in node_datas:
			#print(len(node_data))
			include_record = node_data[0]
			ancestor_record = node_data[1]
			domain_name = node_data[2]

			cypher = ""

			if include_record in domain_list:
				if ancestor_record in domain_list:
			#	domain_node = domain_list[ancestor_record]
			#	include_domain = domain_list[include_record]
					cypher = 'MATCH (a:Domain2 {name:"%s"}),(b:Domain2 {name:"%s"}) CREATE (a)-[:TRUSTS]->(b) ' % (ancestor_record, include_record)

				elif ancestor_record in include_list:
			#	domain_node = spf_include_list[ancestor_record]
			#	include_domain = spf_include_list[include_record]

					cypher = 'MATCH (a:SPFInclude2 {name:"%s"}), (b:Domain2 {name:"%s"}) CREATE (a)-[:TRUSTS]->(b) ' % (ancestor_record, include_record)

			elif include_record in include_list:
				if ancestor_record in include_list:

					cypher = 'MATCH (a:SPFInclude2 {name:"%s"}),(b:SPFInclude2 {name:"%s"}) CREATE (a)-[:TRUSTS]->(b) ' % (ancestor_record, include_record)

				elif ancestor_record in domain_list:
			#	domain_node = domain_list[ancestor_record]
			#	include_domain = spf_include_list[include_record]

					cypher = 'MATCH (a:Domain2 {name:"%s"}), (b:SPFInclude2 {name:"%s"}) CREATE (a)-[:TRUSTS]->(b) ' % (ancestor_record, include_record)

			if cypher:
				try:
#					print(cypher)
					graph.evaluate(cypher)
				except Exception as e:
					print(str(e))
					print("Exception" + str(cypher))
	except Exception as e:
		print(str(e))



def multi_thread_validation(include_data, domain_list, include_list, graph, thread=60):
    """
    use of multiple threads to perform the validation process faster
    """

    index1 = 0
    index2 = 0

    if len(include_data) < thread:
        thread = len(include_data)

    # divide ip_set to blocks for later multiprocess.
    try:
        slice_len = len(include_data) // thread
    except:
        slice_len = 1
    jobs = []

    for i in range(thread - 1):
        if i == 0:
            index1 = i
            index2 = i
        index2 += slice_len

        part = include_data[index1:index2]
        p = Process(target=create_relation, args=(domain_list, include_list, graph, part))
        jobs.append(p)
        p.start()
        index1 += slice_len

    part = include_data[index1:]

    p = Process(target=create_relation, args=(domain_list, include_list, graph, part))
    jobs.append(p)
    p.start()

    # join threads
    for job in jobs:
        if job.is_alive():
            job.join()



if __name__ == '__main__':


	crawling_date = "2018-12-12"

	graph = Graph("http://localhost:7474/db/", auth=("test","test"))
	#tx = graph.begin()

	cypher1 = "CREATE CONSTRAINT ON (n:Domain2) ASSERT n.name IS UNIQUE"
	cypher2 = "CREATE CONSTRAINT ON (n:SPFInclude2) ASSERT n.name IS UNIQUE"

	try:
		graph.evaluate(cypher1)
		graph.evaluate(cypher2)
	except:
		pass

	print("conecting sql")
	db = crawling.connect_database()
	cursor = db.cursor()

	sql_domains = 'select id, domain, spf_policy from spf_records where crawling_date LIKE "{}" and valid=1 '.format(crawling_date)
	cursor.execute(sql_domains)
	domains = cursor.fetchall()

	domain_list = list()
	for domain in domains:
		domain_list.append(domain[1])

	print(len(domain_list))

	p = Pool(processes=70)
	p.map(create_domainnode, domains)


	print("Domains2 created")

	sql_includes = 'SELECT include_record, ANY_VALUE(ancestor_record) from spf_includes where crawling_date LIKE "{}"  group by include_record'.format(crawling_date)
	cursor.execute(sql_includes)

	include_records = cursor.fetchall()

	include_list = list()
	for include in include_records:
		include_list.append(include[0])

	print("Star spf-includes")
	p = Pool(processes=70)
	p.map(create_spfnode, include_records)

	print("Nodes created")

	sql_relation = 'select include_record, ancestor_record, ANY_VALUE(domain) from spf_includes where crawling_date LIKE "{}" group by include_record,ancestor_record;'.format(crawling_date, crawling_date)

	cursor.execute(sql_relation)
	include_data = cursor.fetchall()


	db.close()
	print(len(include_data))
	multi_thread_validation(include_data, domain_list, include_list, graph)


