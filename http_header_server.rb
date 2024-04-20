require 'socket'
require 'json'

BYTES_PER_PACKET = 4096
NUMBER_QUEUED_CONNECTIONS = 5

socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)
socket.setsockopt(:SOCKET, :REUSEADDR, true) # reuse the port if the server is restarted
sockaddr = Socket.pack_sockaddr_in(8081, '0.0.0.0')
socket.bind(sockaddr)
socket.listen(NUMBER_QUEUED_CONNECTIONS)
puts "Listening on port 8081"

def parse_http_request(request)
  headers = {}
  request.split("\r\n").each do |line|
    if line.include?(":")
      key, value = line.split(": ")
      headers[key] = value
    end
  end
  body = request.split("\r\n\r\n")[1]
  [headers, body]
end

def receive_remaining_request_packets(client_socket, headers, body)
  return "" if body.nil?
  expected_content_length = headers["Content-Length"].to_i || 0 
  while body.length < expected_content_length do
    puts 'getting next packet'
    message = client_socket.recv(BYTES_PER_PACKET)
    body += message
  end
  body
end

def build_http_response(headers)
  response = "HTTP/1.1 200 OK\r\n"
  response << "\r\n"
  response << JSON.dump(headers).encode('ascii')
  response
end

loop do
  client_socket, client_addrinfo = socket.accept
  puts "Connection from #{client_addrinfo.inspect}"
  message, sender_sockaddr_in = client_socket.recv(BYTES_PER_PACKET)
  headers, body = parse_http_request(message)
  body = receive_remaining_request_packets(client_socket, headers, body)
  response = build_http_response(headers)
  client_socket.send(response, 0, sender_sockaddr_in)
  client_socket.close
end