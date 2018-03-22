#!/usr/bin/env python
import urllib
import urllib2
import xml.etree.ElementTree as ET
import sys
import json


def palo(pa_ip, pa_key, cmd, parameters):
	
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	
	parameters = json.loads(parameters)
	
	url = "https://"+pa_ip+cmd+"Key="+pa_key+"&"+urllib.urlencode(parameters)
	
	response = urllib2.urlopen(url, context=ctx)
	contents= ET.fromstring(response.read())
	
	result = ""

	if contents.attrib['status'] == "success":
		sys.exit(0)
	else:
		sys.exit(1)


if __name__ == "__main__":
	pa_ip = sys.argv[1]
	pa_key = sys.argv[2]
	cmd = sys.argv[3]
	parameters = sys.argv[4]
	
	palo(pa_ip, pa_key, cmd, parameters)