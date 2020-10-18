#!/usr/bin/python
import json
import getpass
import sys
from optparse import OptionParser
try:
    import requests
except ImportError:
    print "Please install the python-requests module."
    sys.exit(-1)

def get_json(url):
    # Performs a GET using the passed URL location
    r = requests.get(url, auth=(options.username, options.password),timeout=options.timeout, verify=options.verify)
    return r.json()

def call_api(url):
  jsn = get_json(url)
  if jsn.get('error'):
      print "Error: " + jsn['error']['message']
  else:
      if jsn.get('results'):
          return jsn['results']
      elif 'results' not in jsn:
          return jsn
      else:
          print "No results found"
  return None

def grab_id(url):
  id_list = []
  x = call_api(url + "vulnerability/v1/vulnerabilities/cves?data_format=json&show_all=false&page_size=200000")['data']
  for ids in x:
    id_list.append(ids['id'])
  return id_list

def grab_inv_list(url):
  inv_list = []
  x = call_api(url + "vulnerability/v1/systems?page_size=300")['data']
  for inv in x:
    inv_dict = {'hostname': inv['attributes']['display_name'],'cve':[]}
    inv_list.append(inv_dict)
  return inv_list

def cve_to_host(url):
  id_list = grab_id(url)
  cve_list = []
  for cve in id_list:
    cve_dict = {'cve': cve,'hostname':[]}
    x =  get_json(url + "vulnerability/v1/cves/" + cve + "/affected_systems?page_size=200000&data_format=json")['data']
    for y in x:
      cve_dict['hostname'].append(y['attributes']['display_name']) 
    cve_list.append(cve_dict)
  return cve_list

def gen_report(url):
  inv_list = grab_inv_list(url)
  cvh = cve_to_host(url) 
  for a in cvh:
    cve = a['cve']
    for i in inv_list:
      if i['hostname'] in a['hostname']:
        i['cve'].append(cve)
  print inv_list

if __name__ == '__main__':
  usage = "Usuage: %prog ./in.py -u user -c"
  parser = OptionParser(usage=usage)
  parser.add_option("-u", dest="username", help="Add username")
  parser.add_option("-p", dest="password", help="Add password")
  parser.add_option("-v", dest="verify", default="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", help="Ignore untrusted CA")
  parser.add_option("-t", dest="timeout", type="int", default=10, help="Set API timeoute")
  parser.add_option("-c", dest="cve", action='store_true', default=False, help="Create CVE Report")
  parser.add_option("-i", dest="hosts", action='store_true', default=False, help="Use a list of hosts, if your inventory is less than the total number of CVEs or RHSA")
  parser.add_option("-r", dest="rhsa", action='store_true', default=False, help="Create RHSA Report")
  parser.add_option("--url", dest="url", action="store_true", default="https://cloud.redhat.com/api/", help="URL for API Call")
  (options, args) = parser.parse_args()

  if not options.password:
    options.password = getpass.getpass("%s's password:" % options.login)

  if not (options.username and options.cve) or (options.username and options.rhsa): 
    print("You must add a user and to generate a cve report or a rhsa report") 
    sys.exit(1)

  #grab_id(options.url)
  gen_report(options.url)
