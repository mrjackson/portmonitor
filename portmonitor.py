#!/usr/bin/env python3
#./portmonitor.py 204.186.249.254 c20849936594ac95485e908ac9b984665ddd6aa6bbf616f4bbb8b6d5d10f915 mrjackson@gmail.com
import nmap #pip3 install python-nmap
import hashlib
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from datetime import timedelta

logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(filename="/home/mrjackson/log/portmonitor.log", maxBytes=1048576, backupCount=1)
logger.addHandler(handler)
logger.info("Script started: " + str(datetime.now()) + " -- Arguments -- " + str(sys.argv[1:]))
starttime = str(datetime.now())


try:
	hostip = str(sys.argv[1])
	hash = str(sys.argv[2])
	contact = str(sys.argv[3])
except Exception as e:
	logger.error("Script Failed: " + str(datetime.now()) + " -- Arguments Error -- " + str(e))
	sys.exit(1)


def hash_string(string):
	#Return a SHA-256 hash of the given string
	return hashlib.sha256(string.encode('utf-8')).hexdigest()

def sendalertmail(hostip,hash,porthash,portscan,recipient,starttime,endtime,subject):
	#print(hostip,hash,porthash)
	import smtplib
	from email.mime.multipart import MIMEMultipart
	from email.mime.text import MIMEText

	gmailUser = 'misterjackson.house@gmail.com'
	gmailPassword = 'bj002983mh1'
#	recipient = 'misterjackson.house@gmail.com'
	message="External Port Monitoring \n\n" + hostip + "\nGood Hash: " + hash + "\nCurrent Hash: " + porthash + " \n\n" + portscan \
		 + " \n\nStartTime: " + starttime + " \nEndTime: " + endtime

	msg = MIMEMultipart()
	msg['From'] = gmailUser
	msg['To'] = recipient
	msg['Subject'] = subject
	msg.attach(MIMEText(message))

	mailServer = smtplib.SMTP('smtp.gmail.com', 587)
	mailServer.ehlo()
	mailServer.starttls()
	mailServer.ehlo()
	mailServer.login(gmailUser, gmailPassword)
	mailServer.sendmail(gmailUser, recipient, msg.as_string())
	mailServer.close()

try:
	nm = nmap.PortScanner()
	nm.scan(hosts=hostip, arguments='-Pn -r -p 1-65535 --scan-delay 15ms')
	for host in nm.all_hosts():
		portscan = ('----------------------------------------------------\n')
		portscan = portscan + ('Host : %s (%s)' % (host, nm[host].hostname())) + "\n"
		portscan = portscan + ('State : %s' % nm[host].state()) + "\n"
		for proto in nm[host].all_protocols():
			portscan = portscan + ('----------') + "\n"
			portscan = portscan + ('Protocol : %s' % proto) + "\n"

			lport = nm[host][proto].keys()
			#lport.sort()
			for port in lport:
				portscan = portscan + ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state'])) + "\n"
	#print(portscan)
	porthash = hash_string(portscan)
#	print(porthash)

	if (porthash != hash):
		#print("hash failed")
		subject = "ALERT: External Port Monitoring " + host
#		sendalertmail(hostip,hash,porthash,portscan,contact)
	else:
		subject = "INFO: External Port Monitoring " + host

	logger.info(portscan)
	logger.info("Script finished: " + str(datetime.now()) + " -- " + hostip + " -- " + porthash)

except Exception as e:
	logger.error("Script Failed: " + str(datetime.now()) + " -- Run Test -- " + str(e))
	sys.exit(1)

endtime = str(datetime.now())
sendalertmail(hostip,hash,porthash,portscan,contact,starttime,endtime,subject)

#print(portscan)
#porthash = hash_string(portscan)
#print(porthash)
