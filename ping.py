#!/usr/bin/env python

import struct
import time
import socket
import select
import getopt
import os
import sys

icmp_type = 8
icmp_code = 0
icmp_check_sum = 0
icmp_id = 0
icmp_seq_num = 0
icmp_data_size = 56


def construct(size, id):
    '''built up the sending icmp packet
    '''
    if size < struct.calcsize('d'):
        perror('too small for the packet')

    init_header = struct.pack('bbHHh', icmp_type, icmp_code, \
                                icmp_check_sum, icmp_id, icmp_seq_num)
    load = "u can't see me"

    size -= struct.calcsize('d')

    if size > len(load):
        rest = load
        size -= len(load)

    rest += '*' * size

    init_packet = init_header + time.time() + rest

    check_sum = check_sum(init_packet)
    header = struct.pack('bbHHb', icmp_type, icmp_code,\
                            check_sum, icmp_id, icmp_seq_num + id)
    packet = header + time.time() + rest
    return packet


def check_sum(packet):
    '''check the sum in the exsited algotithm '''
    if len(packet) & 1:
        packet += '\0'
    
    words = array.array('h', packet)
    sum = 0

    for word in words:
        sum += (word & 0xffff)

    high = sum >> 16
    low = sum & 0xffff

    sum = high + low
    sum = sum + sum>>16

    return (~sum) & 0xffff

def ping(number = sys.maxint, node = None, size = icmp_data_size):
    if not node:
        perror('...')

    try:
        host = socket.gethostbyname(node)
    except Exception as e:
        perror("can not resolve %s: unknown host" %node)

    if int(host.split('.')[-1]) == 0:
        perror('can not ping network')

    if number == 0:
        perror('have not packet to transmit')

    print 'ping %s (%s): %d data bytes' %(str(node), str(host), 28 + size)
    
    start = 1
    lost = 0
    #avoid ctrl-c and ctrl-z, usding start and lost to confirm running
    while start <= number:
        lost += 1
        try:
            pingSocket = socket.socket(socket.AF_INET,\
                            socket.SOCK_RAW, socket.getprotobyname('icmp'))
        except Exception as e:
            perror(e)

        packet = check_sum(size, start)

        try:
            pingSocket.sendto(packet, (node, 1))
        except Exception as e:
            perror(e)

        pong = ''
        rs = []
        while 1:
            rs, ws, xs = select.select([pingSocket], [], [], timeout)
            break

        if rs:
            end_time = time.time()
            pong, addr = pingSocket.recvfrom(size + 48)
            lost -= 1

            ttl = struct.unpack('s', pong[8])[0]
            ttl16 = int(binascii.hexlify(str(ttl)), 16)
            
            pong_type, pong_code, pong_check_sum, pong_id, pong_seq_num = \
                    struct.unpack('bbHHh', pong[20:28])

            start_time = struct.unpack('d', pong[28:36])

        if pong_seq_num != start:
            pong = None

        if not pong:
            print "ping timeout: %s icmp_seq = %d" %(host, start)

            start += 1
            continue
            
        trip_time = end_time - start_time

        print '%d bytes from %s: icmp_seq = %d ttl = %s, time = %.5f ms'\
                %(size + 8, host, pong_seq_num, ttl16, trip_time)

        start += 1

        pingSocket.close()


def perror(err):
    '''print the error and exit
    '''
    print "%s: %s" %(os.path.basename(sys.argv[0]), str(err))
    print 'try %s --help for more information' \
                %os.path.basename(sys.argv[0])
    sys.exit(1)


def help():
    '''when the user enter --help 
       system prompt the infomation
    '''
    print '''usage: %s [OPTION] HOST
    Send icmp echo_reply packet to network hosts

    arguments to option to setting the utility
    -c  --count=N stop after sending N echo_reply packets
    -s  --size=S specify the number of data bytes to be sent
    -t --timeout=s specify a timeout for the icmp losting
    -h --help show the help information and exit    
    '''%os.path.basename[sys.argv[0]]

if __name__ == "__main__":
    version = str(sys.version[:3]).split('.')
    if map(int, version) <[2, 3]:
        perror("u should update ur python to 2.3 at lease")

    try:
        opts, args = getopt.getopt(sys.argv[1:-1], 'hc:s:', \
                                ["help", "count=", "size="])
    except Exception as e:
        perror("illegal options" + str(e))

    if len(sys.argv) >= 2:
        node = sys.argv[-1:][0]

        if node[0] == '-' or node == '-h' or node == '--help':
            help()
    else:
        perror( str(len(sys.argv))+'is given, but too less')

    size = icmp_data_size
    timeout = 1
    count = sys.maxint

    for o,a in opts:
        if 0 == '-h' or o == '--help':
            help()
        
        if o == '-s' or o == '--size':
            try:
                size = int(a)
            except Exception as e:
                perror('invalid packet size')

        if 0 == '-c' or 0 == '--count':
            try:
                count = int(a)
            except Exception as e:
                perror('invalid count of packet to transmit')

        ping(number = count, node = node, size = size)
        sys.exit(1)
