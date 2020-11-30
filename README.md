# RsaSocketServer
----------
Simple local chat between clients where every message is encrypted and decrypted using **RSA** 

## Description
RsaSocketServer is an application where all clients connected to a server could send private or broadcast encrypted messages using RSA


### SETUP
- Start the server
	```bash
	$ python server.py PORT
	```
- Run the client script using the same **PORT** used for the server 
	```bash
	$ python client.py PORT
	```
- Chat