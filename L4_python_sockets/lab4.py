#!/usr/bin/env python3

import socket
import sys

EXPECTED_LENGTH = 9

try:
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
except (IndexError, ValueError):
    print(f'Usage: {sys.argv[0]} HOST PORT', file=sys.stderr)
    exit(1)


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        while True:
            data = b''

            while len(data) < EXPECTED_LENGTH:
                chunk = sock.recv(EXPECTED_LENGTH - len(data))

                if not chunk:
                    break

                data += chunk

            command = chr(data[0])

            if command == 'Q':
                tmp = int.from_bytes(data[1:5], byteorder='big')
                tmp2 = int.from_bytes(data[5:9], byteorder='big')
                sock.sendall((tmp + tmp2).to_bytes(4, byteorder='big'))

            if command == 'S':
                secret_phrase = data[1:].decode('utf-8')
                print(secret_phrase)
                break


if __name__ == '__main__':
    main()
