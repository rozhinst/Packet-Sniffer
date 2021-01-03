import socket
import struct
import textwrap
from matplotlib import pyplot as plt

labels = 'TCP','UDP','ICMP'
explode = (0,0,0)
fig1,ax1 = plt.subplots()

global icmp_count 
icmp_count = 0
global tcp_count 
tcp_count = 0
global udp_count 
udp_count = 0
global dns_count
dns_count=0
global http_count
http_count = 0

global min_packet_size 
min_packet_size=  1000000000000000000000000000000000000000000000000000000000000000000000
global max_packet_size 
max_packet_size = 0
global total_packets_size
total_packets_size = 0
global fragmented_packets_size
fragmented_packets_size = 0

global ip_packets 
ip_packets = {}
global unique_fragments
unique_fragments = {}
global port_list
port_list = {}


# Unpack Ethernet Frame


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H ', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC addr


def get_mac_addr(bytes_addr):
    bytes_string = map('{:02x}'.format, bytes_addr)
    return':'.join(bytes_string).upper()


def main():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	while True:
		inp = input("Type start to sniff\n")
		if inp == "start":
			break
	capture(conn)


def capture(conn):
	global udp_count
	global tcp_count
	global icmp_count
	while True:
		raw_data, addr = conn.recvfrom(65536)
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print('\nEthernet Frame:')
		print('\t - Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
		if eth_proto == 8:
			(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
			print('\t - IPv4 Packet: ')
			print('\t\t - Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
			print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

			if proto == 1:
				icmp_type, code, checksum, data = icmp_packet(data)
				icmp_count += 1
				print('\t - ICMP Packet: ')
				print('\t\t - Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
				print('\t\t - Data')
				print(format_string('\t\t\t ', data))
			elif proto == 6:
				(src_port, dest_port, sequence, acknowledegment, flag_urg, flag_syn,
				flag_fin, flag_ack, flag_psh, flag_rst, data) = tcp_packet(data)
				tcp_count += 1
				print('\t - TCP Segment: ')
				print('\t\t - Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
				print('\t\t - Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledegment))
				print('\t\t - Flags: ')
				print('\t\t\t - URG: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
				flag_urg, flag_psh, flag_rst, flag_syn, flag_fin))
				print('\t\t - Data')
				print(format_string('\t\t\t ', data))

			elif proto == 17:
				src_port, dest_port, length, data = udp_packet(data)
				udp_count += 1
				print('\t - UDP Segment: ')
				print('\t\t - Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

			else:
				print('\t - Data:')
				print(format_string('\t\t ', data))
		else:
        		print('Data: ')
	        	print(format_string('\t ', data))


def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4
	total_length, id, flags_offset, ttl, proto, src, target = struct.unpack('! 2x 2s 2s 2s B B 2x 4s 4s', data[:20])
	mf = ((int.from_bytes(flags_offset, byteorder="big") >> 4) & 1)
	global total_packets_size
	total_packets_size += int.from_bytes(total_length, "big")
	global max_packet_size
	max_packet_size = max(int.from_bytes(total_length,"big"), max_packet_size)
	global min_packet_size
	min_packet_size = min(int.from_bytes(total_length, "big"), min_packet_size)


	global ip_packets
	global unique_fragments
	global fragmented_packets_size

	if ipv4(src) in ip_packets:
		ip_packets[ipv4(src)] = ip_packets[ipv4(src)] + 1
	else:
		ip_packets[ipv4(src)] = 1

	if ((str(ipv4(src)) + " " + str(id)) in unique_fragments) == False and mf == 1:
		unique_fragments[(str(ipv4(src)) + " " + str(id))] = 1
		fragmented_packets_size += 1

	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_packet(data):
	global dns_count
	global http_count

	(src_port, dest_port, sequence, acknowledgement,offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12)*4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2

	if src_port == 53 or dest_port == 53:
		dns_cout += 1
	if src_port == 80 or dest_port == 80:
		http_count += 1

	if src_port in port_list:
		port_list[src_port] = port_list[src_port] + 1
	else:
		port_list[src_port] = 1

	if dest_port in port_list:
		port_list[dest_port] = port_list[dest_port] + 1
	else:
		port_list[src_port] = 1


	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_syn, flag_fin, flag_ack, flag_psh, flag_rst, data[offset:]


def udp_packet(data):
	global dns_count
	global http_count

	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])

	if src_port == 53 or dest_port == 53:
		dns_count += 1
	if src_port == 80 or dest_port == 80:
		http_count += 1


	if src_port == 53 or dest_port == 53:
		dns_cout += 1
	if src_port == 80 or dest_port == 80:
		http_count += 1

	if src_port in port_list:
		port_list[src_port] = port_list[src_port] + 1
	else:
		port_list[src_port] = 1

	if dest_port in port_list:
		port_list[dest_port] = port_list[dest_port] + 1
	else:
		port_list[src_port] = 1

	return src_port, dest_port, size, data[8:]


def format_string(pref, string, size=80):
    size -= len(pref)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([pref + line for line in textwrap.wrap(string, size)])

def show_graf(total_size):
	sizes = [tcp_count/total_size *100,udp_count/total_size *100,icmp_count/total_size *100]
	ax1.pie(sizes, explode=explode,labels=labels,autopct='%1.1f%%',shadow=True, startangle=90)
	ax1.axis('equal')
	plt.show()

def find_max():
	max_port = max(port_list, key=port_list.get)
	
	return max_port

def write_report():
	count = 0
	outF = open("OutputReport.txt", "w")
	ip_addrs = sorted(ip_packets.items(), key=lambda x: x[1], reverse=True)
	for addr in ip_addrs:
		outF.write(str(addr[0]) + " : " + str(addr[1]))
		count += addr[1]
		outF.write("\n")

	outF.write(
	    "...........................................................................\n")
	outF.write("TCP Count: " + str(tcp_count))
	outF.write("\n")
	outF.write("UDP Count: " + str(udp_count))
	outF.write("\n")
	outF.write("ICMP Count: " + str(icmp_count))
	outF.write("\n")
	outF.write("DNS Count: " + str(dns_count))
	outF.write("\n")
	outF.write("Http Count: " + str(http_count))
	outF.write("\n")
	outF.write("Fragmented Packets Count: " + str(fragmented_packets_size))
	outF.write("\n")
	outF.write("Max Packet Size: " + str(max_packet_size))
	outF.write("\n")
	outF.write("Min Packet Size: " + str(min_packet_size))
	outF.write("\n")
	outF.write("Average Packets Size: " + str(float(total_packets_size/count)))
	outF.write("\n")
	outF.write("Maximum port used: " + str(find_max()))

	outF.close()

	show_graf(count)


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		write_report()
		print('\nSniffing stopped')
		SystemExit(0)

