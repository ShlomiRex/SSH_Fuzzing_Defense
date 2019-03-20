#Fuzzing propability: 1-0.000000017 = 0.999999983

from scapy.all import *
import sys

while True:
	s = sniff(filter="dst port 22", count=1)
#	s.show()
	try:
		#Get payload of Ether, of IP, of TCP, of SSH, and encode it's contents as hexidecimal (remove '<' from the start)
		ssh_payload = s[0].payload.payload.payload.fields['load'][1:].encode('hex')
		'''
		0-9 = 10
		a-z = 26
		total: 36
		P(exactly 5 same symbols are in sequence) = (1/36)^5 = 0.000000017 = Very low
		'''
		
		#Discussed above the propabilities of fuzzing
		num_of_symbols = 5
		#0-9
		for i in range(0, 10):
			#contains num_of_symbols same numbers in a row
			if str(i)*num_of_symbols in ssh_payload:
				print "FUZZING DETECTED!!!! " + ssh_payload
				print "Payload contains: " + str(i)*num_of_symbols
				sys.exit()
		#a-z
		for c in range(97, 123):
			#contains num_of_symbols same ascii in a row
			if chr(c)*num_of_symbols in ssh_payload:
				print "FUZZING DETECTED!!!! " + ssh_payload
				print "Payload contains: " + chr(c)*num_of_symbols
				sys.exit()
	except:
		pass
	

