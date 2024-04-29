import ipaddress
import socket
import ssl
import struct
import sys


NOPRINT_TRANS_TABLE = {
    i: None for i in range(0, sys.maxunicode + 1) if not chr(i).isprintable()
}


def bytes_to_ip(b: bytes):
    return ipaddress.IPv4Address(b)


def domain_to_bytes(domain: str) -> bytes:
    labels = domain.split(".")
    result = b""

    for label in labels:
        label_bytes = label.encode()
        result += bytes([len(label_bytes)]) + label_bytes

    result += b"\x00"
    return result


def parse_response(response: bytes) -> list[str]:
    header = response[:12]
    questions_count = struct.unpack("!H", header[4:6])[0]
    answers_count = struct.unpack("!H", header[6:8])[0]

    res = []
    ptr = 12

    for _ in range(questions_count):
        domain_bytes, ptr = parse_domain_name(response, ptr)
        ptr += 4  # Skip over QTYPE and QCLASS

    for _ in range(answers_count):
        domain_bytes, ptr = parse_domain_name(response, ptr)
        record_type, _, _, rdlength = struct.unpack("!HHIH", response[ptr : ptr + 10])
        ptr += 10

        rdata = response[ptr : ptr + rdlength]
        ptr += rdlength

        domain = bytes_to_domain(domain_bytes)

        if record_type == 1:  # A record
            res.append(f"{domain} A {bytes_to_ip(rdata)}")

        if record_type == 16:  # TXT record
            txt_value = rdata[1 : 1 + rdata[0]].decode()
            res.append(f"{domain} TXT {txt_value}")

    return res


def parse_domain_name(data: bytes, ptr: int) -> tuple[bytes, int]:
    """
    Parse a domain name from the given bytes data and starting offset.
    Returns the domain name as a string and the new offset after parsing.
    """
    domain_name = bytearray()

    while True:
        length = data[ptr]
        ptr += 1

        if length == 0:
            break

        domain_name.extend(data[ptr : ptr + length] + b".")
        ptr += length

    return bytes(domain_name), ptr


def bytes_to_domain(domain_bytes: bytes) -> str:
    """
    Convert a bytes representation of a domain name to a string.
    """
    string_input = domain_bytes.decode()
    parts = [i.translate(NOPRINT_TRANS_TABLE) for i in string_input.split(".")]
    domain_name = ".".join(parts)

    return domain_name


certificate_chain, private_key, resolver_domain, resolver_port = (
    sys.argv[1],
    sys.argv[2],
    sys.argv[3],
    int(sys.argv[4]),
)

context = ssl.create_default_context()
context.load_cert_chain(certificate_chain, private_key)

resolver_ip = socket.getaddrinfo(resolver_domain, resolver_port)[0][4][0]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = context.wrap_socket(sock, server_hostname=resolver_domain)
sock.connect((resolver_ip, resolver_port))

query = struct.pack("!HBBHHHH", 0x1337, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00)
query += domain_to_bytes("evil-corp.ink")
query += struct.pack("!HH", 0x00FF, 0x0001)  # ANY query type and IN class
query = struct.pack("!H", len(query)) + query

sock.sendall(query)
response = sock.recv(4096)
response = response[2:]  # Skip over the length field

for answer in parse_response(response):
    print(answer)

sock.close()
