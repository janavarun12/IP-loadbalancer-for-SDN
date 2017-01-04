import socket

HOST = '10.10.10.10'
PORT = 8080
ADDR = (HOST,PORT)
BUFSIZE = 1024
videofile = "pox/ext/bigfile.mp4"

bytestream = open(videofile).read()

print len(bytestream)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)
print('Sending....')
client.send(bytestream)

client.close()
