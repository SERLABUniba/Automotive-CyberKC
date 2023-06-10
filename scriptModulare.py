#! /usr/bin/python

import socket
import pickle
import argparse
import binascii
import os
from time import sleep


HOST = ('127.0.0.1', 514)


def init_sock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return sock

def send_normal(sock, source_ip, id):

    data = binascii.b2a_hex(os.urandom(8))

    message = '{"UUID": "' + id +'", "UUID_ECU": "f1b186f8fc", "vehicleModel": "TestVehicleModel", "eventID": "send payload", "eventCategory": "flow", "sourceIP": "' + source_ip + '", "Timestamp": "1478198376.389427", "ID CAN": "00a0", "DLC": 8, "DATA CAN": "' + data + '"}'

    for _ in range(0, 5):
        sock.sendto(pickle.dumps(message), HOST)
        sleep(1)

def send_dos(sock, source_ip, id):
    
    message = '{"UUID": "' + id +'", "UUID_ECU": "f1b186f8fc", "vehicleModel": "TestVehicleModel", "eventID": "send payload", "eventCategory": "flow", "sourceIP": "' + source_ip + '", "Timestamp": "1478198376.389427", "ID CAN": "0000", "DLC": 8, "DATA CAN": "00 00 00 00 00 00 00 00"}'

    for _ in range(0, 5):
        sock.sendto(pickle.dumps(message), HOST)
        sleep(1)


def send_fuzzing(sock, source_ip, id):

    message = '{"UUID": "' + id +'", "UUID_ECU": "f1b186f8fc", "vehicleModel": "TestVehicleModel", "eventID": "send payload", "eventCategory": "flow", "sourceIP": "' + source_ip + '", "Timestamp": "1478198376.389427", "ID CAN": "1111", "DLC": 8, "DATA CAN": "11 11 11 11 11 11 11 11"}'

    for _ in range(0, 5):
        sock.sendto(pickle.dumps(message), HOST)
        sleep(1)


def main():
    sock = init_sock()
    parser = argparse.ArgumentParser(
                    prog = 'Script QRadar',
                    description = 'Send DoS and Fuzzing attack to QRadar',
                    epilog = 'args attack -a [dos, fuzzing] additional param [-ip]')
    parser.add_argument("-n", required=False, help="If you want to send 5 test messages.'", action='store_true', default='normal')
    parser.add_argument("-a", type=str, choices=["dos", "fuzzing"], required=False, help="Choose either 'dos' or 'fuzzing'.")
    parser.add_argument("-ip", type=str, required=False, default='192.168.1.1', help="Enter a Source IP default [192.168.1.1].")
    parser.add_argument("-id", type=str, required=True, help="Enter an UUID.")

    args = parser.parse_args()

    if args.a == 'dos':
        send_dos(sock, str(args.ip), str(args.id) )
    elif args.a == 'fuzzing':
        send_fuzzing(sock, str(args.ip), str(args.id))
    else:
        send_normal(sock, str(args.ip), str(args.id))
    

if __name__ == '__main__':
    main()
