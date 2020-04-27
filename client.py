import socket
import json
import rsa
import threading
import sys

class Client:
	DISCONNECT_MESSAGE = "!DISCONNECT"

	def __init__(self, ADDR, username):
		self.ADDR = ADDR
		self.username = username
		self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.active_users = []
		self.priv = 0
		self.pub = 0

	def send(self, receiver, msg):
		data = {"sender": self.username, "receiver": receiver, "msg": msg}
		self.client.send(json.dumps(data).encode())

	def update_users(self, users):
		self.active_users = users
		self.active_users.remove(self.username)
		self.active_users.append("broadcast")

	def listen(self):
		self.client.send(self.username.encode())
		while True:
			data = self.client.recv(1024).decode()
			data = json.loads(data)
			if "users" in data.keys():
				self.update_users(data["users"])
			else:
				print(f"\n[NEW MESSAGE] {data['sender']}: {data['msg']} \nMessage: ", end="")

	def run(self):
		print(f"[CONNECTION] Starting connection to {ADDR}")
		try:
			self.client.connect(self.ADDR)
			thread = threading.Thread(target=self.listen)
			thread.start()
			while True:
				msg = input("Message: ")
				if msg != self.DISCONNECT_MESSAGE:
					print(f"\n[ACTIVE USERS] {self.active_users}")
					receiver = input("Receiver: ")
					if receiver not in self.active_users:
						print(f"not a valid username")
						continue
				self.send(receiver, msg)
		except Exception as e:
			print(e)
			self.client.close()
			exit(0)


IP = socket.gethostbyname(socket.gethostname())
PORT = int(sys.argv[1])
ADDR = (IP, PORT)


username = input("Insert username: ")
client = Client(ADDR, username)
client.run()
