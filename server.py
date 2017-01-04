import socket
import sys

hostName = sys.argv[1]   
portNo = int(sys.argv[2])

conn_counter = open('pox/ext/ConnectionCounters/counter_'+hostName+'.txt', 'w')
conn_counter.write('0')
conn_counter.close()


HOST = hostName
PORT = portNo
ADDR = (HOST,PORT)
BUFSIZE = 1024


serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("binding socket",ADDR)
serv.bind(ADDR)
serv.listen(5)

print 'listening ...'


while True:
  conn, addr = serv.accept()
  print 'client connected ... ', addr
  myfile = open('testfile.mp4', 'w')



  while True:
    data = conn.recv(BUFSIZE)
    if not data: break
    myfile.write(data)
    print 'writing file ....'

  myfile.close()
  print 'finished writing file'
  conn.close()
  conn_counter = open('pox/ext/ConnectionCounters/counter_'+hostName+'.txt', 'w')
  conn_counter.write('0')
  print("connection closed")
  conn_counter.close()
  print 'client disconnected'




