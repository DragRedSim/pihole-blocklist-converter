#!/usr/bin/env python3
import re
import os
import argparse 
import urllib3
import requests
import sqlite3 as lite
import subprocess

### --- DEBUG --- ###
# import logging

# # These two lines enable debugging at httplib level (requests->urllib3->http.client)
# # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# # The only thing missing will be the response.body which is not logged.
# try:
#     import http.client as http_client
# except ImportError:
#     # Python 2
#     import httplib as http_client
# http_client.HTTPConnection.debuglevel = 1

# # You must initialize logging, otherwise you'll not see debug output.
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True
### --- DEBUG --- ###

def arg_parse():
	''' Argparser.
	'''
	parser = argparse.ArgumentParser(description='Convert AdBlock list to text')
	URL = parser.add_argument(
		'url',
		type=str,
		help='input url',
		nargs='?',
		default="https://cdn.cashrewards.com/whitelist/network-cash-back-shopping.txt")
	local_args = parser.parse_args()
	return local_args

def cleanCSV(bList):
	''' Clean CSVs.
		- remove domains with *
	'''
	aList = []
	for item in bList.split(","):
		if not("*" in item):
			aList.append(item)
	return aList

def checkCSV(string):
	''' Check string for CSV.
		- looks for ##, #@# and #
	'''
	s = False
	for n in range(0, len(string)):
		if string[n] == "*":
			s = True
		if string[n] == "#":
			if s == False:
				return string[:n].split(",")
			if s == True: 
				return cleanCSV(string[:n])

def cleanAdstr(string):
	'''	Get domain from string.
		- excludes: wildcards, incomplete domains
	'''
	for n in range(0, len(string)):
		if string[n] == ("*" or ".js" or "/"):
			break
		if string[n] == "^":
			return string[:n]
		if string[n] == "$":
			break

def getFilename(inURL):
	''' Get filename from URL.
		- first "/" from right
	'''
	for n in range(0, len(inURL)):
		if inURL[-n] == "/":
			return inURL[len(inURL)-n+1:]

def getAdList(inURL):
	''' Get raw blocklist text file.
	'''
	requests.packages.urllib3.disable_warnings()
	res = requests.get(inURL)
	if not ("text/plain" in res.headers['content-type']):	#  check content type is plain text
		raise Exception("Content Type: ", res.headers['content-type'], " does not match text/plain.")
	if res.status_code != 200:	#  check OK response
		raise Exception("Status Code: ",res.status_code," Error: ",res.text)
	if res.text == None:	# check for data
		raise Exception("No data in response. ",res.headers, res.text)
	return res.text

def writeList(inURL, adList, newFile):
	''' Create parsed blocklist file.
	'''
	csvStack = []
	writer = open(newFile, 'w')
	writer.write("# Converted by: https://github.com/anthonytwh/pihole-blocklist-converter"+"\n")
	writer.write("# Blocklist: "+inURL+"\n")
	for line in adList.splitlines():
		if line:
			try:
				if line.startswith(("#", "!", "/", "|", "-", "@", "*", "^", "$")) == False:
					lineList = checkCSV(line)
					if (lineList) and (lineList != csvStack):
						writer.writelines("\n".join(lineList)+"\n")
					csvStack = lineList 	# don't write duplicate lists
			except:
				pass

			try: 
				if line.startswith("@@||") == True:
					line = cleanAdstr(line[4:])
					if line:
						callWhitelist(line)
						writer.write("@@"+line+"\n")
			except: 
				pass

			try: 
				if line.startswith("||") == True:
					line = cleanAdstr(line[2:])
					if line:
						writer.write(line+"\n")
			except: 
				pass

def chk_conn(conn):
	try:
		conn.cursor()
		return True
	except Exception as ex:
		return False

def callWhitelist(domain):

	cur = con.cursor()
	#search if already in list
	cur.execute('SELECT seq FROM sqlite_sequence WHERE name = "domainlist"')
	idout = cur.fetchone()
	idnum = idout[0] + 1
	cur.execute('SELECT * FROM domainlist WHERE domain = ?', (domain, ))
	check=cur.fetchone()
	if check is None:
		#not in list, add it
		cur.execute('INSERT INTO domainlist (id, type, domain, enabled, comment) VALUES(?,0,?,1,"Cashrewards")', (idnum, domain))
		cur.execute('UPDATE sqlite_sequence SET seq = ? WHERE name = "domainlist"', (idnum, ))

	cur.execute('INSERT OR IGNORE INTO domainlist_by_group VALUES(?,5)', (idnum, ))
	con.commit()

def main(inURL):
	''' Main.
	'''
	adList = getAdList(inURL)
	fileName = getFilename(inURL)
	currDir = os.getcwd()
	newFile = currDir + "/filters/" + fileName
	try:
		print(f"Connection status: {chk_conn(con)}")
	except Error as e:
		print(e)

	writeList(inURL, adList, newFile)

	con.close()
	print("Disconnected from gravity DB")
	process = subprocess.Popen(["pihole", "-g"], stdout=subprocess.PIPE)
	output, error = process.communicate()

args = arg_parse()
con = lite.connect('/etc/pihole/gravity.db') #used for automatically whitelisting

if args.url:
	main(args.url)
