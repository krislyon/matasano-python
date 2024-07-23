# Python of SHA1 from Chat Gippity.

import struct

H = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
K = [0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6]
def hash_sha1(message):
    message = bytearray(message)
    ml = len(message) * 8  # original message length in bits
    message.append(0x80)   # append a single '1' bit
    while len(message) % 64 != 56:
        message.append(0x00)  # append zeros until length is 64 bits less than a multiple of 512
    message += struct.pack('>Q', ml)  # append ml as 64-bit big-endian integer

    # Process each 512-bit chunk
    for offset in range(0, len(message), 64):
        chunk = message[offset:offset + 64]

        # Break chunk into sixteen 32-bit big-endian words
        w = list(struct.unpack('>16I', chunk))

        # Extend the sixteen 32-bit words into eighty 32-bit words
        for i in range(16, 80):
            w.append(rotate_left((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1))

        # Initialize hash value for this chunk
        a, b, c, d, e = H

        # Main loop
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = K[0]
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = K[1]
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = K[2]
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = K[3]

            temp = (rotate_left(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far
        H[0] = (H[0] + a) & 0xFFFFFFFF
        H[1] = (H[1] + b) & 0xFFFFFFFF
        H[2] = (H[2] + c) & 0xFFFFFFFF
        H[3] = (H[3] + d) & 0xFFFFFFFF
        H[4] = (H[4] + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian)
    hash_hex = '{:08x}{:08x}{:08x}{:08x}{:08x}'.format(*H)
    return bytes.fromhex(hash_hex)

def rotate_left(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def hmac_sha1( message:bytes, key:bytes ):
    pt = bytearray(key)
    pt.extend(message)
    return hash_sha1(pt)
    
