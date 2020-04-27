import socket
import json
import threading
import sys
import time


class Server:
	def __init__(self, ADDR):
		self.ADDR = ADDR
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.bind(ADDR)
		self.active_users = {}

	def send_list_active_users(self):
		for user, conn in self.active_users.items():
			users = {"users": list(self.active_users.keys())}
			conn.send(json.dumps(users).encode())
	
	def send_message(self, receiver, msg, sender):
		data = {"sender": sender, "msg": msg}
		if receiver == "broadcast":
			for user, conn in self.active_users.items():
				conn.send(json.dumps(data).encode())
		else:
			conn = self.active_users[receiver]
			conn.send(json.dumps(data).encode())

	def disconnect_client(self, username, client):
		print(f"[DISCONNECTING] {username}")
		client.send("DISCONNECTING".encode())
		client.close()
		del self.active_users[username]
		self.send_list_active_users()

	def handle_client(self, conn, addr):
		username = conn.recv(1024).decode()
		self.active_users[username] = conn
		self.send_list_active_users()
		while True:
			msg = conn.recv(1024).decode()
			data = json.loads(msg)
			if data["msg"] == "!DISCONNECT":
				self.disconnect_client(username, conn)
			else:
				self.send_message(data["receiver"], data["msg"], data["sender"])

	def run(self):
		print("[STARTING] server is starting...")
		try:
			self.server.listen()
			print(f"[LISTENING] Server is listening on {ADDR}")
			while True:
				conn, addr = self.server.accept()
				thread = threading.Thread(target=self.handle_client, args=(conn, addr))
				thread.start()
				time.sleep(1)
				print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")
				print(f"[USERS] {list(self.active_users.keys())}")
		except Exception as e:
			print(e)
			self.server.close()


IP = socket.gethostbyname(socket.gethostname())
PORT = int(sys.argv[1])
ADDR = (IP, PORT)

server = Server(ADDR)
server.run()