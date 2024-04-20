require 'socket'

# To run locally and watch for changes in the file
# ls simple_dns_server.rb | entr ruby simple_dns_server.rb pillarseclabs.com

class DNSClient
  attr_reader :dns_socket, :dns_server_domain, :dns_server_port, :dns_server, :xid
  def initialize(domain = '8.8.8.8', port = 53)
    @dns_socket = Socket.new Socket::AF_INET, Socket::SOCK_DGRAM
    @dns_server_domain = domain
    @dns_server_port = port
    @dns_server = Socket.sockaddr_in(@dns_server_port, @dns_server_domain)
    @xid = Random.new.rand(1000)
  end


  def find_ip_address!
    query = QueryPacker.new(xid, ARGV[0]).pack!
    p 'sending query'
    dns_socket.send(query, 0, dns_server)
    message, sender_addrinfo = dns_socket.recvfrom(4096)
    p 'received message' if message
    HeaderParser.new(xid, dns_server_domain, dns_server_port, sender_addrinfo).parse!(message)
    p ResponseParser.new(message).parse!
  end
end

class QueryPacker
  def initialize(xid, hostname)
    @xid = xid
    @hostname = hostname
  end

  def pack!
    pack_headers + pack_question_section
  end

  private

  attr_reader :xid, :hostname
  def pack_headers
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

  def pack_question_section
    q_type = 1 # default to A record
    q_class = 1 # default to IN class
    packed_q_name + [q_type, q_class].pack('n2')
  end

  def packed_q_name
    hostname.split('.').map do |label|
      # C packs the length as a single octet, rather than unsigned short (two octets)
      [label.length].pack("C") +
        label.encode('ascii')
    end.join('') + "\x00" # null byte, signify an end to the query name
  end
end

class ResponseParser
  SIZE_OF_QTYPE_AND_QCLASS_IN_BYTES = 4
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

  RESPONSE_BYTE_RANGES = {
    'name': 0..1,
    'type': 2..3,
    'rdata_class': 4..5,
    'ttl': 6..9,
    'rd_length': 10..11,
  }
  attr_reader :message, :qsection_and_response

  def initialize(message)
    # message should be question and response
    @message = message
    @qsection_and_response = message[12..-1]
  end

  def parse!
    end_query_section_idx = find_end_of_query_section(qsection_and_response, 0) + SIZE_OF_QTYPE_AND_QCLASS_IN_BYTES
    response_record = qsection_and_response[end_query_section_idx..-1]
    pointer_index = extract_name_pointer(response_record[0..1])
    p "response for domain name: #{parse_name(message, pointer_index)}"
    type = DNS_RECORD_TYPES[response_record[2..3].unpack("n1")[0]]
    rdata_class = RDATA_CLASS_TYPES[response_record[4..5].unpack("n1")[0]]
    ttl = response_record[6..9].unpack("L1")[0] # skip caching behavior for now
    rd_length = response_record[10..11].unpack("n1")[0]
    rdata = response_record[12..(12 + rd_length)]
    p "#{type} record for #{rdata.bytes.join(".")}"
    rdata.bytes.join(".")
  end

  private

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

  def rdata_byte_range(rd_length)
    12..(12 + rd_length)
  end
end

class HeaderParser
  attr_reader :request_xid

  def initialize(request_xid, dns_server_address, dns_server_port, sender_addrinfo)
    @request_xid = request_xid
    response_domain, response_port = sender_addrinfo.inspect_sockaddr.split(":")
    unless dns_server_address == response_domain && dns_server_port.to_s == response_port.to_s
      raise 'response address and port does not match the query address and port'
    end
  end

  def parse!(message)
    # only need to unpack the first 12 bytes, since that's the standard
    # query format
    xid, metadata, qd_count, an_count, ns_count, ar_count = message.unpack("n12") 
    parse_metadata(metadata)
    raise "response XID does not match request XID" if xid != request_xid
    p 'header parsed'
  end

  private

  # metadata refers to second set of octects describe in the header fields 
  # of RFC-1035, Section 4.1.1.
  # since these individual codes require parsing on a bit-level scale,
  # this method converts the data to binary and splits the binary string
  # based on specified boundaries.
  def parse_metadata(metadata)
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
end

DNSClient.new.find_ip_address!