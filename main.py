from datetime import datetime
import socket, argparse, random, shlex

# Consts
SOCKET_BUF_SIZE = 2048
MAX_CHALLENGES = 128
SERVER_PROTOCOL = '48'
BUILD_NUMBER = '8308'

# Global variables
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
challenges = [] # Challenges list
clients = [] # Connected clients
server_password = '' # Server user password
cuserid = 1 # Current max user id

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
	sock.sendto(b'\xff\xff\xff\xff' + ('9' + text + '\n').encode('ascii'), address)

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
		cuserid += 1
		clients.append(clientinfo)
		return True

def bswap(i):
	return struct.unpack("<I", struct.pack(">I", i))[0]

def UnMunge2(data, length, seq):
	mungelist = [0xFFFFE7A5, 0xBFEFFFE5, 0xFFBFEFFF, 0xBFEFBFED, 0xBFAFEFBF, 0xFFBFAFEF, 0xFFEFBFAD, 0xFFFFEFBF, 0xFFEFF7EF, 0xBFEFE7F5, 0xBFBFE7E5, 0xFFAFB7E7, 0xBFFFAFB5, 0xBFAFFFAF, 0xFFAFA7FF, 0xFFEFA7A5]
	mseq = bswap(~seq) ^ seq
	length /= 4 # Amount of longs in message
	times = length // 16
	rest = length % 16
	newdata = [int.from_bytes(data[i] + data[i+1] + data[i+2] + data[i+3], 'little') for i in range(0,len(data),4)]

	if times != 0:
		for i in range(0, times - 1):
			newdata[16*i] = bswap(newdata[16*i] ^ mseq ^ mungelist[0])
			newdata[16*i + 1] = bswap(newdata[16*i + 1] ^ mseq ^ mungelist[1])
			newdata[16*i + 2] = bswap(newdata[16*i + 2] ^ mseq ^ mungelist[2])
			newdata[16*i + 3] = bswap(newdata[16*i + 3] ^ mseq ^ mungelist[3])
			newdata[16*i + 4] = bswap(newdata[16*i + 4] ^ mseq ^ mungelist[4])
			newdata[16*i + 5] = bswap(newdata[16*i + 5] ^ mseq ^ mungelist[5])
			newdata[16*i + 6] = bswap(newdata[16*i + 6] ^ mseq ^ mungelist[6])
			newdata[16*i + 7] = bswap(newdata[16*i + 7] ^ mseq ^ mungelist[7])
			newdata[16*i + 8] = bswap(newdata[16*i + 8] ^ mseq ^ mungelist[8])
			newdata[16*i + 9] = bswap(newdata[16*i + 9] ^ mseq ^ mungelist[9])
			newdata[16*i + 10] = bswap(newdata[16*i + 10] ^ mseq ^ mungelist[10])
			newdata[16*i + 11] = bswap(newdata[16*i + 11] ^ mseq ^ mungelist[11])
			newdata[16*i + 12] = bswap(newdata[16*i + 12] ^ mseq ^ mungelist[12])
			newdata[16*i + 13] = bswap(newdata[16*i + 13] ^ mseq ^ mungelist[13])
			newdata[16*i + 14] = bswap(newdata[16*i + 14] ^ mseq ^ mungelist[14])
			newdata[16*i + 15] = bswap(newdata[16*i + 15] ^ mseq ^ mungelist[15])

	newdata[16 * times + (rest - 1)] = bswap(newdata[16 * times + (rest - 1)] ^ mseq ^ mungelist[rest - 1])

	return newdata

def ProcessMessage(address, data):
	seq = int.from_bytes(data[0:4], 'little')
	if seq < 0:
		seq = seq & 0xffffffff # Shall be unsigned
	seq_ack = int.from_bytes(data[4:8], 'little')
	if seq_ack < 0:
		seq_ack = seq_ack & 0xffffffff # Shall be unsigned
	message = seq >> 31;
	ack = seq_ack >> 31;
	contain_fragments = True if seq & (1 << 30) else False
	#print(message,ack,contain_fragments)
	print(UnMunge2(data[8:], len(data)-8, seq & 0xff))

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
	parser = argparse.ArgumentParser(description='pyHLDS')
	parser.add_argument('-ip', metavar='ADDRESS', help='bind address')
	#parser.add_argument('-p', metavar='PORT', help='server port')
	parser.add_argument('-sv_password', metavar='PASSWORD', help='server password')
	#parser.add_argument('+map', metavar='MAP', help='map')
	args = parser.parse_args()

	print("pyHLDS by KiriXon")
	print("=================")

	try:
		sock.bind((args.ip, 27015))
	except sock.error:
		print('ERROR binding socket')

	print("Listening on port 27015")

	global server_password
	server_password = args.sv_password

	while True:
		received = sock.recvfrom(SOCKET_BUF_SIZE)
		data = received[0]
		address = received[1]
		print(address, data)

		if (data[0:4] == b'\xff\xff\xff\xff'):
			ProcessUnconnected(address, data[4:])
			continue

		ProcessMessage(address, data)

	sock.close()

if __name__ == '__main__':
    main()
