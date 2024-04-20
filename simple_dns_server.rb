require 'socket'

dns_socket = Socket.new Socket::AF_INET, Socket::SOCK_DGRAM
DNS_SERVER_PORT = 53
google_dns_server = Socket.sockaddr_in(DNS_SERVER_PORT, "8.8.8.8")

# To run locally and watch for changes in the file
# ls simple_dns_server.rb | entr ruby simple_dns_server.rb pillarseclabs.com

# TODO: make xid random on each request
SIZE_OF_QTYPE_AND_QCLASS_IN_BYTES = 4
xid = 75 # some unique id that helps identify the mailbox

DNS_RECORD_TYPES = {
  1 => "A",
  2 => "NS",
  3 => "MD",
  4 => "MF",
  5 => "CNAME",
  6 => "SOA",
  7 => "MB",
  8 => "MG",
  9 => "MR",
  10 => "NULL",
  11 => "WKS",
  12 => "PTR",
  13 => "HINFO",
  14 => "MINFO",
  15 => "MX",
  16 => "TXT"
}

RDATA_CLASS_TYPES = {
  1 => "IN",
  3 => "CH",
  4 => "HS",
  255 => "ANY"
}



def construct_query_headers(xid)
  # left shift bit, which indicates that I'm setting the 9th position with a 1
  # this is necessary to indicate that we are setting the Recursion Desired flag
  flags = (1 << 8) 
  qd_count = 1
  an_count = 0
  ns_count = 0
  ar_count = 0
  # n6 signifies that we're packing the 6 two-byte octets in big-endian format
  [xid, flags, qd_count, an_count, ns_count, ar_count].pack('n6')
end

def construct_query_domain_name
  hostname = ARGV[0]
  hostname.split('.').map do |label|
    # C packs the length as a single octet, rather than unsigned short (two octets)
    [label.length].pack("C") +
      label.encode('ascii')
  end.join('') + "\x00" # null byte, signify an end to the query name
end

def construct_question_section
  q_name = construct_query_domain_name
  q_type = 1
  q_class = 1
  q_name + [q_type, q_class].pack('n2')
end
query = construct_query_headers(xid) + construct_question_section
p "query"
p query
dns_socket.send(query, 0, google_dns_server)
message, sender_addrinfo = dns_socket.recvfrom(4096)
p "response"

def parse_response_header(unpacked_message)
  xid, metadata, qd_count, an_count, ns_count, ar_count = unpacked_message
  # verify that xid that is return matches xid that was passed
  formatted_metadata = metadata.to_s(2) # convert to binary (base 2)
  qr = formatted_metadata[0] # qr should be equal to 1, indicating a response
  opcode = formatted_metadata[1..4] # should be 0, since this is a standard query
  aa = formatted_metadata[5]
  tc = formatted_metadata[6]
  rd = formatted_metadata[7] # should be 1, since we requested it to be used
  ra = formatted_metadata[8] # should also be 1, since we expect dns servers to have recursion available
  z = formatted_metadata[9..11]
  rcode = formatted_metadata[12..15]
end

def find_end_of_query_section(qsection_and_payload, index)
  return index + 1 if qsection_and_payload.bytes[index] == 0
  find_end_of_query_section(qsection_and_payload, index + qsection_and_payload.bytes[index] + 1)
end

def parse_name(qsection_and_payload, index)
  return '' if qsection_and_payload.bytes[index] == 0
  qsection_and_payload.byteslice(
    index + 1, 
    qsection_and_payload.bytes[index]) + 
    "." +
  parse_name(
    qsection_and_payload, 
    index + qsection_and_payload.bytes[index] + 1)
end

def extract_name_pointer(name_bytestring)
  unpacked_name_bytestring = name_bytestring.unpack("CC")
  # flip first two bits of first bit to assert that flags are present, as per spec
  byte_with_flags = unpacked_name_bytestring[0] ^ 0xC0
  raise "missing flags indicator" unless byte_with_flags == 0
  # repack as bytes, then repack as 16-bit unsigned to find actual pointer address
  [byte_with_flags, unpacked_name_bytestring[1]].pack("CC").unpack("n1")[0]
end

def parse_response(message)
  p message
  header = message[0..11]
  qsection_and_response = message[12..-1]
  end_query_section_idx = find_end_of_query_section(qsection_and_response, 0) + SIZE_OF_QTYPE_AND_QCLASS_IN_BYTES
  response_record = qsection_and_response[end_query_section_idx..-1]
  p pointer_index = extract_name_pointer(response_record[0..1])
  p parse_name(message, pointer_index)
  p type = DNS_RECORD_TYPES[response_record[2..3].unpack("n1")[0]]
  p rdata_class = RDATA_CLASS_TYPES[response_record[4..5].unpack("n1")[0]]
  p ttl = response_record[6..9].unpack("L1")[0] # skip caching behavior for now
  p rd_length = response_record[10..11].unpack("n1")[0]
  p rdata = response_record[12..(12 + rd_length)]
  p rdata.bytes.join(".")

  # p (name_bytes[0].hex ^ 0xC0).to_s(2)

  # p (response[0] ^ 0xC0) + response[1]
  # p 'response name:' + response[0..1] ^ "\xC0"

  # TODO: how do I know how many pointers are included and, if there are multiple pointers,
  # are they all broken up by a null byte?
  # p response
  # p message[12]
  # p response.bytes.map { |byte| byte.to_s(2) }

end
parse_response(message)

p "ok"