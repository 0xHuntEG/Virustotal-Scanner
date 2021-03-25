from __future__ import print_function
import requests
import re
import sys

# Validate the user input:
def get_input():
    if len(sys.argv) <= 1:
        print("[+] Usage: python3 Virustotal_Scanner.py [URL or Domain or IP or file Hash]")
        sys.exit(1)
    else:
        return sys.argv[1]
get_input()

API = "Enter Your API" 	# Add Your API key Here


# Search by URL:
def URL_search():
    URL = (sys.argv[1])
    URL_REGEX = re.search(r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%.\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%\+.~#?&//=]*)", URL)
    if URL_REGEX:
        url = "https://www.virustotal.com/vtapi/v2/url/report?apikey={0}&resource={1}".format(API, URL)
        print("URL being queried: {}".format(url))
        response = requests.get(url)
        #print(response.text)
        MA_REGEX  = re.findall(r'("positives": )([0-9]*)', response.text)
        #print(MA_REGEX[0][1])
        if int(MA_REGEX[0][1]) > 0:
            print("This is a Malicious URL")
        else:
            print("This is a Clean URL")

        sys.exit(1)
URL_search()

