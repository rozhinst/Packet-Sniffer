import socket
import struct
import textwrap


icmp_count = 0
tcp_count = 0
udp_count = 0


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
        inp = input("Type start to sniff")
        if inp == "start":
            break

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('\t - Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            (version, header_length, ttl, proto,
             src, target, data) = ipv4_packet(data)
            print('\t - IPv4 Packet: ')
            print(
                '\t\t - Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(
                '\t\t - Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                icmp_count += 1
                print('\t - ICMP Packet: ')
                print(
                    '\t\t - Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print('\t\t - Data')
                print(format_string('\t\t\t ', data))
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledegment, flag_urg, flag_syn,
                 flag_fin, flag_ack, flag_psh, flag_rst, data) = tcp_packet(data)
                tcp_count += 1
                print('\t - TCP Segment: ')
                print(
                    '\t\t - Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(
                    '\t\t - Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledegment))
                print('\t\t - Flags: ')
                print('\t\t\t - URG: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                    flag_urg, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t\t - Data')
                print(format_string('\t\t\t ', data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_packet(data)
                udp_count += 1
                print('\t - UDP Segment: ')
                print(
                    '\t\t - Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

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
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_packet(data):
    (src_port, dest_port, sequence, acknowledgement,
     offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12)*4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_syn, flag_fin, flag_ack, flag_psh, flag_rst, data[offset:]


def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def format_string(pref, string, size=80):
    size -= len(pref)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([pref + line for line in textwrap.wrap(string, size)])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Sniffing stopped')
