#!/usr/bin/python3
# coding: utf-8

import time, threading, argparse, requests, json, socket, os, numbers
from datetime import datetime

VERSION 					= '0.9'
POLYCUBED_ADDR 				= 'localhost'
POLYCUBED_PORT 				= 9000
REQUESTS_TIMEOUT 			= 10
OUTPUT_DIR 					= 'dump'
FEATURES 					= ['Date first seen'.ljust(29), 'Duration(ns)'.ljust(15), 'Proto'.ljust(10), 'Src IP Addr:Port'.ljust(44), 'Dst IP Addr:Port'.ljust(44), 'Flags'.ljust(8), 'Tos'.ljust(5), 'Packets'.ljust(10), 'Bytes'.ljust(10), 'Flows'.ljust(8)]
INTERVAL 					= 300   		 	# seconds to wait before retrieving again the features, to have less just insert a decimal number like 0.01
protocol_map 				= dict(			# map protocol integer value to name
	[(6, "TCP"), (17, "UDP"), (1, "ICMP"), (58, "ICMPv6")])

polycubed_endpoint = 'http://{}:{}/polycube/v1'
counter = 0

def main():
	global polycubed_endpoint

	args = parseArguments()

	addr = args['address']
	port = args['port']
	cube_name = args['cube_name']
	output_dir = args['output']
	interval = args['interval']

	polycubed_endpoint = polycubed_endpoint.format(addr, port)

	checkIfOutputDirExists(output_dir)

	dynmonConsume(cube_name, output_dir, interval)


def dynmonConsume(cube_name, output_dir, interval):
	global counter
	parsed_entries = []
	my_count = counter
	counter += 1
	
	start_time = time.time()
	metrics =  getMetrics(cube_name)
	req_time = time.time()

	threading.Timer(interval, dynmonConsume, (cube_name, output_dir, interval)).start()

	ipv4 = metrics[0]['value'] if len(metrics) == 3 and 'value' in metrics[0] and metrics[0]['value'] is not None else []
	ipv6 = metrics[1]['value'] if len(metrics) == 3 and 'value' in metrics[1] and metrics[1]['value'] is not None else []

	if not ipv4 and not ipv6:
		print(f'Got nothing ...\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')
		return

	parseAndStore(ipv4+ipv6, output_dir, my_count)
	print(f'Got something!\n\tExecution n°: {my_count}\n\tTime to retrieve metrics: {req_time - start_time} (s)\n\tTime to parse: {time.time() - req_time} (s)')


def arrayToIPv6(values):
	address = ''
	column_cnt = 1
	for crtLong in values:
		for i in range(0,4):
			byte1 = hex(crtLong & 0xFF).lstrip("0x")
			byte2 = hex((crtLong >> 8) & 0xFF).lstrip("0x")
			if not byte1 and not byte2:
				column_cnt += 1
				if column_cnt > 2: 
					crtLong = crtLong >> 16
					continue
			else: column_cnt = 1

			address = address + ":" + byte1 + (byte2.zfill(2) if byte1 else byte2)
			crtLong = crtLong >> 16
	return address[1:]


def timestampToDate(timestamp):
	return datetime.fromtimestamp(timestamp // 1000000000).strftime('%Y-%m-%d %H:%M:%S') + '.' + str(int(timestamp % 1000000000)).zfill(9)


def flagsToString(flags):
	return f'{"C" if (flags & 0x80) else "."}{"E" if (flags & 0x40) else "."}{"U" if (flags & 0x20) else "."}{"A" if (flags & 0x10) else "."}{"P" if (flags & 0x8) else "."}{"R" if (flags & 0x4) else "."}{"S" if (flags & 0x2) else "."}{"F" if (flags & 0x1) else "."}'


def parseAndStore(entries, output_dir, counter):
	data = []
	flows = {}
	fp = open(f"{output_dir}/dump{counter}.csv", 'w')
	fp.write('\t'.join(x for x in FEATURES) + '\n')

	for entry in entries:
		key = entry['key']
		value = entry['value']
		if isinstance(key['saddr'], numbers.Number):
			saddr = f'{socket.inet_ntoa(key["saddr"].to_bytes(4, "little"))}:{socket.ntohs(key["sport"])}'
			daddr = f'{socket.inet_ntoa(key["daddr"].to_bytes(4, "little"))}:{socket.ntohs(key["dport"])}'
		else:
			saddr = f'{arrayToIPv6(key["saddr"])}.{socket.ntohs(key["sport"])}'
			daddr = f'{arrayToIPv6(key["daddr"])}.{socket.ntohs(key["dport"])}'

		fp.write(f'{str(timestampToDate(value["start_timestamp"])).ljust(29)}\t{str(value["alive_timestamp"] - value["start_timestamp"]).ljust(15)}\t{protocol_map[key["proto"]].ljust(10)}\t' 
			f'{saddr.ljust(44)}\t'
			f'{daddr.ljust(44)}\t'
			f'{flagsToString(value["flags"]).ljust(8)}\t{str(value["tos"]).ljust(5)}\t{str(value["packets"]).ljust(10)}\t{str(value["bytes"]).ljust(10)}\t{str(value["flows"]).ljust(5)}\n')

	fp.close()



def checkIfOutputDirExists(output_dir):
	try:
		os.mkdir(output_dir)
	except IOError:
		print(f"Directory {output_dir} already exists")
	except OSError:
		print (f"Creation of the directory {output_dir} failed")
	else:
		print (f"Successfully created the directory {output_dir}")


def getMetrics(cube_name):
	try:
		response = requests.get(f'{polycubed_endpoint}/dynmon/{cube_name}/metrics/ingress-metrics', timeout=REQUESTS_TIMEOUT)
		if response.status_code == 500:
			print(response.content)
			exit(1)
		response.raise_for_status()
		return json.loads(response.content)
	except requests.exceptions.HTTPError:
		return False, None
	except requests.exceptions.ConnectionError:
		print('Connection error: unable to connect to polycube daemon.')
		exit(1)
	except requests.exceptions.Timeout:
		print('Timeout error: unable to connect to polycube daemon.')
		exit(1)
	except requests.exceptions.RequestException:
		print('Error: unable to connect to polycube daemon.')
		exit(1) 


def showVersion():
    return '%(prog)s - Version ' + VERSION


def parseArguments():
	parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('cube_name', help='indicates the name of the cube', type=str)
	parser.add_argument('-a', '--address', help='set the polycube daemon ip address', type=str, default=POLYCUBED_ADDR)
	parser.add_argument('-p', '--port', help='set the polycube daemon port', type=int, default=POLYCUBED_PORT)
	parser.add_argument('-o', '--output', help='set the output directory', type=str, default=OUTPUT_DIR)
	parser.add_argument('-i', '--interval', help='set time interval for polycube query', type=float, default=INTERVAL)
	parser.add_argument('-v', '--version', action='version', version=showVersion())
	return parser.parse_args().__dict__


if __name__ == '__main__':
	main()