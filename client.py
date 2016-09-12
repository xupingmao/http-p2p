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
import functools
import threading

def rand_bytes(num):
	return reduce(operator.add, ('%c' % random.randint(0, 255) for i in range(num)))

def fail(reason):
	sys.stderr.write(reason + '\n')
	sys.exit(1)

def get_table(key):
	m = hashlib.md5()
	m.update(key.encode("utf-8"))
	s = m.digest()
	# < litter-endian
	# q stands for long long , 8 bytes
	(a, b) = struct.unpack('<QQ', s)
	# string.maketrans returns a string (length=256) in python2
	# str.maketrans returns a dict in python3
	# table = [c for c in str.maketrans('', '')] # get list of 256 chars
	table = []
	for c in range(256):
		table.append(c)
	for i in range(1, 1024):
		#  table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
		table.sort(key = functools.cmp_to_key(lambda x, y: int(a % (x + i) - a % (y + i))))
	# return trans dict
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


class TcpServer():

	def __init__(self):
		# threading.Thread.__init__(self)
		try:
			ip = "127.0.0.1"
			self.ip = ip
			# tcp socket
			self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.tcp_socket.bind((ip, PORT))
			socket.setdefaulttimeout(10)
			print("bind tcp at %s:%s" % (ip, PORT))
			self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.udp_socket.bind(("", CLIENT_UDP_SERVER_PORT))
			print("bind udp at %s" % CLIENT_UDP_SERVER_PORT)
			# import pdb
			# pdb.set_trace()
		except Exception as e:
			print_traceback(e)
			fail('Failed to bind on port ' + str(PORT))
		self.knownServer = (SERVER, SERVER_PORT)

	def run(self):
		client_addr = None
		self.tcp_socket.listen(5)
		while True:
			try:
				# receive tcp request
				conn, addr = self.tcp_socket.accept()
				print("[TCP] -- ", addr)

				# import pdb
				# pdb.set_trace()

				data = conn.recv(8192)
				print("[TCP] -- ", data)
				# put time tag on the request
				self.udp_socket.sendto(data, self.knownServer)
				resp_data = b''
				received = 0
				while True:
					udp_data, udp_addr = self.udp_socket.recvfrom(1024 * 256)
					print("[UDP] -- ", udp_addr)
					# udp_data has one byte of status header
					# TODO check data sequence

					# first 4 bytes are sequence number
					_seq = udp_data[:3]
					_data = udp_data[4:]
					if _seq == b'ffff': # end
						# resp_data += udp_data[1:]
						if len(_data) > 0:
							conn.send(_data)
						break
					else:
						# TODO check sequence
						# seq = int(_seq)
						conn.send(_data)
						received += 1
						# resp_data += udp_data[1:]
				# udp_data = b"hello,world"
				# conn.sendall(resp_data)
				conn.close()
			except socket.timeout as e:
				print_traceback(e)
				conn.sendall(b'timeout')
				conn.close()
			except KeyboardInterrupt as e:
				print_traceback(e)
				self.udp_socket.close()
				self.tcp_socket.close()
				sys.exit(1)
			except Exception as e:
				print_traceback(e)
				conn.close()
			# finally:
				# self.udp_socket.close()
				# self.tcp_socket.close()
				
				# self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				# self.tcp_socket.bind((self.ip, PORT))
				# self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				# self.udp_socket.bind(("", SERVER_PORT))


if __name__ == '__main__':
	os.chdir(os.path.dirname(__file__) or '.')
	
	try:
		with open('config.json', 'r') as f:
			config = json.load(f)
		SERVER                 = config['server']
		SERVER_PORT            = config['server_port']
		CLIENT_UDP_SERVER_PORT = config["client_udp_server_port"]
		PORT                   = config['client_port']
		KEY                    = config['password']
	except Exception as e:
		print_traceback(e)

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
	# encrypt_table = get_table(KEY)
	# decrypt_table = str.maketrans(encrypt_table, str.maketrans('', ''))
	t = TcpServer()
	t.run()

	# try:
	# 	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	# 	s.bind(('', PORT))
	# except:
	# 	fail('Failed to bind on port ' + str(PORT))

	# knownClient = None
	# knownServer = (SERVER, SERVER_PORT)
	# while True:
	# 	data, addr = s.recvfrom(65535)

	# 	if addr == knownServer: # receive data from remote server
	# 		# result, data = decrypt(data)
	# 		# if not result or knownClient is None:
	# 		# 	continue
	# 		if knownClient is None:
	# 			continue
	# 		s.sendto(data, knownClient) # send data back to local client
	# 	else: # receive data from local client
	# 		knownClient = addr
	# 		# s.sendto(encrypt(data), knownServer)
	# 		s.sendto(data, knownServer) # send data to remote server


