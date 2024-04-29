import hashlib


def sha_256(b: bytes) -> bytes:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(b)

    return sha256_hash.digest()


# Feel free to edit the main function however you like to help you debug, it won't be graded
#
# Run this script with the command: python3 part2.py
# or select "Part 2" from the VS Code debugger
def main():
    digest = sha_256(b"Hello, world!")
    print(digest)


if __name__ == "__main__":
    main()
