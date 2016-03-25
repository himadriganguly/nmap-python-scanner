import nmap
import argparse
import threading
from threading import Thread

def nmapScan(tgtHost, lock, tgtPort=''):
	with lock:
		nmapScan = nmap.PortScanner()
		if tgtPort:
			nmapScan.scan(tgtHost, tgtPort, arguments='-O')
			state = nmapScan[tgtHost]['tcp'][int(tgtPort)]['state']
			print('[+] {0} tcp/{1} {2}'.format(tgtHost, tgtPort, state))
		else:
			print(nmapScan.csv())
			for proto in nmapScan[tgtHost].all_protocols():
				lport = nmapScan[tgtHost][proto].keys()
				for port in lport:
					state = nmapScan[tgtHost][proto][int(port)]['state']
					print('[+] {0} {1}/{2} {3}'.format(tgtHost, proto, port, state))

def main():
	parser = argparse.ArgumentParser('Nmap Port Scanner In Python')
	parser.add_argument('host', type=str, help='Host IP address to scan')
	parser.add_argument('-p', '--port', type=str, help='Port numbers to be scanned. Enter port number seperated by comma. -p 80,21')
	args = parser.parse_args()
	# if (args.port == None):
		# print('Both Hostname and Port Number required\n')
		# parser.print_help()
		# exit(0)
	tgtHost = args.host
	if(args.port):
		tgtPorts = str(args.port).split(',')
	print('==============================')
	print('Starting Nmap Scan')
	print('==============================')
	lock = threading.Lock()
	if(args.port):
		for tgtPort in tgtPorts:
			t = Thread(target=nmapScan, args=(tgtHost, lock, tgtPort))
			t.start()
			# nmapScan(tgtHost, tgtPort)
	else:
		t = Thread(target=nmapScan, args=(tgtHost, lock))
		t.start()

if __name__ == '__main__':
	main()
	
