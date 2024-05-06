require 'socket'

class DNSClient
  DNS_RECORD_TYPES = {
    "A" => 1,
    "NS" => 2,
    "CNAME" => 5,
    "MX" => 15,
    "TXT" => 16
  }
  attr_reader :dns_socket, :dns_server_domain, :dns_server_port, :dns_server, :xid
  def initialize(domain = '8.8.8.8', port = 53)
    @dns_socket = Socket.new Socket::AF_INET, Socket::SOCK_DGRAM
    @dns_server_domain = domain
    @dns_server_port = port
    @dns_server = Socket.sockaddr_in(@dns_server_port, @dns_server_domain)
    @xid = Random.new.rand(1000)
  end


  def find_ip_address!
    q_type = ARGV[1] ? DNS_RECORD_TYPES[ARGV[1]] || 1 : 1
    query = QueryPacker.new(xid:, hostname: ARGV[0], q_type:).pack!
    p 'sending query'
    dns_socket.send(query, 0, dns_server)
    message, sender_addrinfo = dns_socket.recvfrom(4096)
    p 'received message' if message
    header = HeaderParser.new(xid, dns_server_domain, dns_server_port, sender_addrinfo)
    header.parse!(message)
    p 'header parsed!'
    response = ResponseParser.new(header:, message:).parse!
    response.each { |answer| puts answer }
  end
end

class QueryPacker
  def initialize(xid:, hostname:, q_type:)
    @xid = xid
    @hostname = hostname
    @q_type = q_type
  end

  def pack!
    pack_headers + pack_question_section
  end

  private

  attr_reader :xid, :hostname, :q_type
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
  DNS_RECORD_TYPES = {
    1 => "A",
    2 => "NS",
    5 => "CNAME",
    15 => "MX",
    16 => "TXT"
  }

  RDATA_CLASS_TYPES = {
    1 => "IN",
  }
  attr_reader :message, :header

  def initialize(header:, message:)
    @header = header
    @message = message
  end

  def parse!
    current_index = current_index_after_query_section
    current_index, name, type, rd_class, ttl = parse_rdata(current_index)
    rd_length_raw, current_index = extract_data_and_update_index(current_index, 2)
    p "parsing response of #{type} record for #{name}"
    case type
    when 'A'
      rd_length = rd_length_raw.unpack("n1").first
      rd_data, _ = extract_data_and_update_index(current_index, rd_length)
      [rd_data.bytes.join(".")]
    when 'NS'
      Array.new(header.an_count) do |_|
        current_index, name, type, rd_class, ttl = parse_rdata(current_index + 1)
        rd_data, current_index = extract_data_and_update_index(current_index, 4)
        name
      end
    end
  end

  private

  def parse_name(message, index)
    next_byte = message.bytes[index]
    return ['', index] if next_byte == 0 # reached end if null byte
    if next_byte & 0b11000000 == 192 # if label is pointer
      # pointer is a 2 octect sequence
      most_significant_byte, least_significant_byte = message.bytes[index..index + 1]
      # XOR to flip 2 left bits since they're used as an indicator
      # then shift left by 8 to create a 16 bit number
      # then OR the least significant byte to get the correct value of the pointer
      pointer = (most_significant_byte ^ 0b11000000) << 8 | least_significant_byte
      name, _ = parse_name(message, pointer)
      return [name, index]
    end
    label_size = next_byte

    previous_labels, next_idx = parse_name(
      message, 
      index + 1 + label_size) 
    name = message[index + 1..index + label_size] +
      "." +
      previous_labels
    [name, next_idx]
  end

  def extract_data_and_update_index(index, number_of_bytes)
    data = message[index + 1..index + number_of_bytes]
    index += number_of_bytes
    [data, index]
  end

  def current_index_after_query_section
    num_bytes_in_qtype_and_qclass = 4
    num_bytes_in_header = 12
    name, current_index = parse_name(message, num_bytes_in_header)
    # technically, end of query section is 1 byte _after_ the null byte
    current_index += num_bytes_in_qtype_and_qclass + 1 
    current_index
  end

  def parse_rdata(current_index)
    response_name, current_index = parse_name(message, current_index)
    response_type, current_index = extract_data_and_update_index(current_index + 1, 2)
    rd_class, current_index = extract_data_and_update_index(current_index, 2)
    ttl, current_index = extract_data_and_update_index(current_index, 4)
    [
      current_index,
      response_name,
      DNS_RECORD_TYPES[response_type&.unpack('n1')&.first],
      RDATA_CLASS_TYPES[rd_class&.unpack('n1')&.first],
      ttl&.unpack("L1")&.first,
    ]
  end
end

class HeaderParser
  attr_reader :request_xid, :an_count

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
    @an_count = an_count
    parse_metadata(metadata)
    raise "response XID does not match request XID" if xid != request_xid
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

# p test_string = "\x03app\rpillarseclabs\x03com\x00\x03fig\xC0"
# name, next_idx = parse_name(test_string, 0)
# p name
# p test_string[next_idx]

# p test_string = "\x03app\rpillarseclabs\x03com\x00\x03fig\xC0"
# name, next_idx = parse_name(test_string, 23)
# p name
# p test_string[next_idx]

# p more_complex_string = "\x03app\rpillarseclabs\x03com\x00\x04arpa\x03fig\xC0"
# name, next_idx = parse_name(more_complex_string, 23)
# p "name should be arpa.fig.app.pillarseclabs.com.: #{name == 'arpa.fig.app.pillarseclabs.com.'}"
# p "next_idx should be 32 (end of string): #{33 == next_idx} #{next_idx} #{more_complex_string.length}"
# p more_complex_string[next_idx]

# p 'test using pointer alone'
# more_complex_string = "\x03app\rpillarseclabs\x03com\x00\x03abi\x03fig\xC0"
# name, next_idx = parse_name(more_complex_string, 31)
# p "name should be app.pillarseclabs.com.: #{name == 'app.pillarseclabs.com.'}"
# p more_complex_string[next_idx]