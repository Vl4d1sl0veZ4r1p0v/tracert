# coding=utf-8
from tracert.trace import Trace
from tracert.parse import get_args
import socket


args = get_args()
destination = args.host
try:
    print("Start processing")
    with Trace(destination) as tracer:
        results = tracer.go()
        for num, result in enumerate(results):
            print(f'{num + 1} {result}\r\n')
except socket.gaierror:
    print(f'Address {destination} is invalid')
except PermissionError:
    print('Not enough rights for access to socket')