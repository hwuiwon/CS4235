#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "https://cryptoproject.gtinfosec.org/GTusername/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
from typing import Union, Dict, List
from Crypto.Cipher import AES

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write(
                "It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n"
            )
            sys.stderr.write(
                "If this keeps happening, check the URL. Perhaps your GTusername is not set.\n"
            )
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)

    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)

    b_list = []
    diff = [0] * AES.block_size
    msg = bytearray(message)

    num_blocks = len(msg) // AES.block_size
    n = num_blocks - 2

    tmp = bytearray(msg)

    for i in range(256):
        tmp[(n + 1) * AES.block_size - 1] = i
        status = oracle(oracle_url, [tmp])[0]["status"]

        if status in ["valid", "invalid_mac"]:
            c = msg[(n + 1) * AES.block_size - 1]
            b_list.append(
                {
                    "p": 1 ^ c ^ i,
                    "status": status,
                }
            )

    if len(b_list) == 2 and b_list[0]["status"] != "invalid_mac":
        p = b_list[1]["p"]
    else:
        p = b_list[0]["p"]

    padding = p
    diff[AES.block_size - 1] = p ^ c
    decode = (p.to_bytes((p.bit_length() + 7) // 8, "big")).hex()
    tmp = bytearray(msg)

    for i in range(AES.block_size - 2, -1, -1):
        for j in range(AES.block_size - 1, i, -1):
            tmp[n * AES.block_size + j] = (AES.block_size - i) ^ diff[j]

        for j in range(256):
            tmp[n * AES.block_size + i] = j
            status = oracle(oracle_url, [tmp])[0]["status"]

            if status in ["valid", "invalid_mac"]:
                t = AES.block_size - padding

                if (status == "valid" and i > t) or (
                    status == "invalid_mac" and i == t
                ):
                    continue

                c = msg[n * AES.block_size + i]
                p = (AES.block_size - i) ^ c ^ j
                diff[i] = p ^ c
                decode = (p.to_bytes((p.bit_length() + 7) // 8, "big")).hex() + decode

                break

        tmp = bytearray(msg)

    msg = msg[0 : AES.block_size * (num_blocks - 1)]
    tmp = bytearray(msg)

    for i in range(num_blocks - 3, -1, -1):
        for j in range(AES.block_size - 1, -1, -1):
            for k in range(AES.block_size - 1, j, -1):
                tmp[i * AES.block_size + k] = (AES.block_size - j) ^ diff[k]

            for k in range(256):
                tmp[i * AES.block_size + j] = k
                status = oracle(oracle_url, [tmp])[0]["status"]

                if status in ["valid", "invalid_mac"]:
                    c = msg[i * AES.block_size + j]
                    p = (AES.block_size - j) ^ c ^ k
                    diff[j] = p ^ c
                    decode = (
                        p.to_bytes((p.bit_length() + 7) // 8, "big")
                    ).hex() + decode

                    break

            tmp = bytearray(msg)

        msg = msg[: AES.block_size * (i + 1)]
        tmp = bytearray(msg)

    decoded_bytes = bytes.fromhex(decode)
    decoded_bytes = decoded_bytes[: len(decoded_bytes) - padding - 32]
    decoded_text = decoded_bytes.decode("ascii", errors="ignore")

    print(decoded_text)


if __name__ == "__main__":
    main()
