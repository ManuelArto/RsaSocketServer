import socket
import json
import rsa
from binascii import hexlify
import os
import threading
import sys

class Client:
	DISCONNECT_MESSAGE = "!DISCONNECT"

	def __init__(self, ADDR, username):
		self.ADDR = ADDR
		self.username = username
		self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.active_users = {}
		self.generate_key()

	def generate_key(self):
		try:
			with open(f'{self.username}/priv.key', 'rb') as f:
				priv_file_content = f.read()
			self.privkey = rsa.PrivateKey.load_pkcs1(priv_file_content)
		except IOError:
			os.mkdir(self.username)
			(self.pubkey, self.privkey) = rsa.newkeys(512)
			with open(f'{self.username}/pub.key', 'wb') as f:
				f.write(self.pubkey.save_pkcs1())
			with open(f'{self.username}/priv.key', 'wb') as f:
				f.write(self.privkey.save_pkcs1())
		finally:
			with open(f'{self.username}/pub.key', 'rb') as f:
				pub_file_content = f.read()
			self.pubkey = pub_file_content.decode()

	def send_broadcast(self, msg):
		for receiver in self.active_users:
			self.send(receiver, msg)

	def send(self, receiver, msg):
		pubkey_recv = rsa.key.PublicKey.load_pkcs1(self.active_users[receiver])
		crypto = rsa.encrypt(msg, pubkey_recv)
		data = {"sender": self.username, "receiver": receiver, "msg": crypto.hex()}
		self.client.send(json.dumps(data).encode())

	def update_users(self, users):
		del users[self.username]
		self.active_users = users

	def init_data(self):
		data = {"username": self.username, "pubkey": self.pubkey}
		self.client.send(json.dumps(data).encode())

	def listen(self):
		self.init_data()
		while True:
			data = self.client.recv(1024).decode()
			data = json.loads(data)
			if "users" in data.keys():
				self.update_users(data["users"])
			else:
				crypto = bytes.fromhex(data["msg"])
				msg = rsa.decrypt(crypto, self.privkey).decode()
				print(f"\n[NEW MESSAGE] {data['sender']}: {msg} \nMessage: ", end="")

	def run(self):
		print(f"[CONNECTION] Starting connection to {ADDR}")
		self.client.connect(self.ADDR)
		thread = threading.Thread(target=self.listen)
		thread.start()
		while True:
			msg = input("Message: ")
			if msg != self.DISCONNECT_MESSAGE:
				print(f"\n[ACTIVE USERS] {list(self.active_users.keys()) + ['broadcast']}")
				receiver = input("Receiver: ")
				if receiver not in list(self.active_users.keys()) + ["broadcast"]:
					print(f"not a valid username")
					continue
			if receiver == "broadcast":
				self.send_broadcast(msg.encode())
			else:
				self.send(receiver, msg.encode())


IP = socket.gethostbyname(socket.gethostname())
PORT = int(sys.argv[1])
ADDR = (IP, PORT)


username = input("Insert username: ")
client = Client(ADDR, username)
client.run()
