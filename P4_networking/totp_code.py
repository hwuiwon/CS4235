# Some imports that we think may be useful to you.
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import parse_qs, urlparse
import base64
import hmac
import sys
import time


def hotp(key: str, counter: int, digits: int) -> str:
    # Convert the key and counter to bytes
    key_bytes = base64.b32decode(key)
    counter_bytes = counter.to_bytes(8, byteorder="big")

    # Calculate the HMAC
    digest = hmac.new(key_bytes, counter_bytes, "sha1").digest()

    # Apply the dynamic truncation
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], byteorder="big") & 0x7FFFFFFF

    # Truncate and apply padding
    hotp_value = str(binary % (10**digits)).rjust(digits, "0")

    return hotp_value


def totp(key: str, time_step: int, digits: int) -> str:
    # Calculate the current counter value
    current_time = int(time.time() // time_step)
    return hotp(key, current_time, digits)


# Read the QR code data
contents = decode(Image.open(sys.argv[1]))[0].data.decode()
parsed_uri = urlparse(contents)

# Extract the parameters from the URI
params = parse_qs(parsed_uri.query)
secret_key = params["secret"][0]
time_step = int(params["period"][0])
digits = int(params.get("digits", [6])[0])

# Calculate the TOTP code
totp_code = totp(secret_key, time_step, digits)

print(totp_code)
