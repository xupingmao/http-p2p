#!/usr/bin/env python

# Super simple script that listens to a local UDP port and relays all packets to an arbitrary remote host.
# Packets that the host sends back will also be relayed to the local UDP client.
# Works with Python 2 and 3

import os
import hashlib
import sys 
import socket
import struct
import string
import json
import getopt
import random
import operator
import traceback

def rand_bytes(num):
	return reduce(operator.add, ('%c' % random.randint(0, 255) for i in range(num)))

def fail(reason):
	sys.stderr.write(reason + '\n')
	sys.exit(1)

def get_table(key):
	m = hashlib.md5()
	m.update(key)
	s = m.digest()
	(a, b) = struct.unpack('<QQ', s)
	table = [c for c in string.maketrans('', '')]
	for i in xrange(1, 1024):
		table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
	return table

#md5 hash 16 bytes
def encrypt(data):
	h = hashlib.md5(data).digest()
	if len(data) <= 50:
		padlength = 150
	elif len(data) <= 100:
		padlength = 100
	elif len(data) <= 150:
		padlength = 50
	else:
		padlength = 10
	return (h + struct.pack('<H', padlength) + rand_bytes(padlength) + data).translate(encrypt_table)

# hash(16) + padlength(unsigned int, 2) + pad + data
def decrypt(data):
	if len(data) <= 150:
		return (False, '')
	de = data.translate(decrypt_table)
	padlength, = struct.unpack('<H', de[16:18]);
	h = de[:16]
	data = de[18 + padlength:]

	if hashlib.md5(data).digest() != h:
		return (False, data)
	return (True, data)

def print_traceback(e):
	ex_type, ex, tb = sys.exc_info()
	print(ex_type, ":", ex)
	traceback.print_tb(tb)


def respond(app):
	resp = app.request(url)
	data = resp.data
	headers = resp.headers
	status  = resp.status
	

def request_by_raw(host, port, request):
	http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	socket.setdefaulttimeout(30)
	http_sock.connect((host,port))
	http_sock.sendall(request)
	# http_fp = http_sock.makefile("rb")
	while True:
		# line = http_fp.readline(1024 * 256 - 4)
		line = http_sock.recv(1024 * 256 - 4)
		if len(line)==0:
			# http_fp.close()
			http_sock.close()
			raise StopIteration()
		else:
			yield line


if __name__ == '__main__':
	os.chdir(os.path.dirname(__file__) or '.')
	
	try:
		with open('config.json', 'r') as f:
			config = json.load(f)
		SERVER = config['server']
		SERVER_PORT = config['server_port']
		PORT = config['proxy_port']
		KEY = config['password']
	except:
		ex_type, ex, tb = sys.exc_info()
		print(ex)
		traceback.print_tb(tb)
		print("warning, config.json not found or can not be opened\n")

	optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:')
	for key, value in optlist:
		if key == '-p':
			SERVER_PORT = int(value)
		elif key == '-k':
			KEY = value
		elif key == '-l':
			PORT = int(value)
		elif key == '-s':
			SERVER = value

	# encrypt_table = ''.join(get_table(KEY))
	# decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind(('', SERVER_PORT))
		print("bind on port", SERVER_PORT)
	except Exception as e:
		print_traceback(e)
		fail('Failed to bind on port ' + str(SERVER_PORT))

	knownClient = None
	knownServer = (SERVER, SERVER_PORT)
	while True:
		data, addr = s.recvfrom(65535)
		print("[UDP] -- ", addr)
		for data in request_by_raw("localhost", 8080, data):
			s.sendto(b'0000' + data, addr)
		s.sendto(b'ffff', addr)
		# s.sendto(b'shello,world from udp<br/>', addr)
		# s.sendto(b'cfirst try<br/>', addr)
		# s.sendto(b'elast try', addr)


		# if addr == knownServer: # receive data from local server
		# 	if not knownClient is None:
		# 		# s.sendto(encrypt(data), knownClient)
		# 		s.sendto(data, knownClient) # send data to remote client
		# else: # receive data from remote client
		# 	# result, data = decrypt(data)
		# 	# if not result:
		# 		# continue
		# 	knownClient = addr
		# 	s.sendto(data, knownServer) # send data to local server


