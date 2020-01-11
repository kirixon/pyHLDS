from datetime import datetime
import socket
import random
import shlex

# Consts
SOCKET_BUF_SIZE = 2048
MAX_CHALLENGES = 128
SERVER_PROTOCOL = '48'
BUILD_NUMBER = '8308'

# Global variables
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
challenges = [] # Challenges list
clients = [] # Connected clients
server_password = 'kaminari' # Server user password
cuserid = 1

def GetChallenge(addr):
	curtime = datetime.now()
	res = next((item for item in challenges if item['address'] == addr), None)
	challenge = (random.randint(0,36863) << 16) | random.randint(0,65535)
	if (res != None):
		challenges.remove(res)
	challenges.append({ 'address': addr, 'challenge': challenge, 'time': curtime })

	if len(challenges) > MAX_CHALLENGES:
		challenges.pop(0)

	return challenge

def RejectConnection(address, text):
	sock.sendto(b'\xff\xff\xff\xff' + '9'.encode('ascii') + text.encode('ascii') + '\n'.encode('ascii'), address)

def CheckChallenge(address, challenge):
	res = next((item for item in challenges if item['address'] == address), None)
	if ((res != None) and (res['challenge'] == challenge)):
		return True
	else:
		RejectConnection(address, 'Bad challenge.')
		return False

def CheckProtocol(address, cprotocol):
	if (cprotocol != SERVER_PROTOCOL):
		RejectConnection(address, 'Bad protocol.')
		return False
	else:
		return True

def CheckInfo(address, info):
	info = info.split('\\')
	info.remove('')
	clientinfo = {info[i]: info[i + 1] for i in range(0, len(info), 2)}

	if (clientinfo['password'] != server_password):
		RejectConnection(address, 'Bad password.')
		return False
	else:
		global cuserid
		clientinfo.update({'userid': cuserid, 'connected': True, 'active': False, 'spawned': False, 'uploading': False, 'fully_connected': False, 'address': address})
		cuserid = cuserid + 1
		clients.append(clientinfo)
		return True

def ProcessUnconnected(address, data):
	data = shlex.split(data.decode('ascii').rstrip('\n'))
	cmd = data[0]
	data.remove(cmd)

	if (cmd == 'getchallenge'):
		# TODO: Steam challenge
		sock.sendto(b'\xff\xff\xff\xffA00000000 ' + str(GetChallenge(address)).encode('ascii') + b' 2\n', address)
	elif (cmd == 'challenge'):
		pass
	elif (cmd == 'connect'):
		# TODO: Key verification, LAN restriction, etc
		if (len(data) < 4):
			RejectConnection(address, 'Insufficient connection info.')
		if not CheckChallenge(address, int(data[1])):
			return
		if not CheckProtocol(address, data[0]):
			return
		if not CheckInfo(address, data[3]):
			return

		sock.sendto(b'\xff\xff\xff\xffB ' + str(clients[-1]["userid"]).encode('ascii') + b' \"' + address[0].encode('ascii') + b':' + str(address[1]).encode('ascii') + b'\" 0 ' + BUILD_NUMBER.encode('ascii') + b'\n', address)

		print('Client connected: {} ({})'.format(clients[-1]["name"], address))

	elif (cmd == 'rcon'):
		pass

def main():
	print("pyHLDS by KiriXon")
	print("=================")

	try:
		sock.bind(('172.16.24.154', 27015))
	except sock.error:
		print('ERROR binding socket')

	print("Listening on port 27015")

	while True:
		received = sock.recvfrom(SOCKET_BUF_SIZE)
		data = received[0]
		address = received[1]
		print(address, data)

		if (data[0:4] == b'\xff\xff\xff\xff'):
			ProcessUnconnected(address, data[4:])
			continue

		

	sock.close()

if __name__ == '__main__':
    main()
