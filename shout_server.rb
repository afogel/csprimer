require 'socket'

u1 = UDPSocket.new
u1.bind("127.0.0.1", 8080)
loop do
  mesg, addr = u1.recvfrom(1024)
  u1.send(mesg.upcase, 0, addr[3], addr[1])
end
