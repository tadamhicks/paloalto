#!/usr/bin/env python
import urllib
import urllib2
import xml.etree.ElementTree as ET
import sys
import json
import ssl


def palo(pa_ip, pa_key, cmd, RULENAME=None, IP_ADDR=None, call_type):
	
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	
	if call_type == "A":

		parameters = {
			"xpath": "/config/devices/entry/vsys/entry[@name=\'vsys4\'']/rulebase/security/rules/entry[@name=%s]" % (RULENAME), 
			"element": """
			<source><member:Inbound-Global-F5</member></source>
			<destination><member>%s</member></destination>
			<service><member>application-default</member></service>
			<application>
			<member>ssl</member>
			<member>ping</member>
			</application>
			<category><member>any</member></category>
			<hip-profiles><member>any</member></hip-profiles><action>allow</action><source-user><member>any</member></source-user>
			<log-start>yes</log-start>
			<log-end>no</log-end>
			<description>morpheus testing</description>
			<from><member>infra-untrust</member></from>
			<to><member>infra-public</member></to>
			""" % (IP_ADDR)
		}
	elif call_type == "B":

		parameters = {
			"xpath": "/config/devices/entry/vsys/entry[@name=\'vsys4\']/rulebase/security/rules/entry[@name=%s]" % (RULENAME),
			"where": "before", 
			"dst": "Deny All"
		}
	elif call_type == "C":
		parameters = {
			"cmd": "<commit></commit>"
		}
	else:
		print "INSUFFICIENT CALL TYPE"
		sys.exit(1)
	
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
	RULENAME = sys.argv[4]
	IP_ADDR = sys.argv[5]
	call_type = sys.argv[6]
	
	palo(pa_ip, pa_key, cmd, RULENAME, IP_ADDR, call_type)