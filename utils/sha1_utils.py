# Python of SHA1 from Chat Gippity.

import struct
import random

def sha1_hash(message,debug_state=False):
    return sha1_hash_set_state( message, debug_state=debug_state )

def sha1_hash_set_state( message, STATE_A=0x67452301, STATE_B=0xEFCDAB89, STATE_C=0x98BADCFE, STATE_D=0x10325476, STATE_E=0xC3D2E1F0, forcelen=False, debug_state=False ):

    def rotate_left(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    H = [STATE_A, STATE_B, STATE_C, STATE_D, STATE_E]
    K = [0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6]

    message = bytearray(message)

    # Apply padding if it was passed (for forgery), otherwise calculate it and apply it.
    if( forcelen ):
        ml = forcelen * 8
    else:
        ml = len(message) * 8  # original message length in bits
    message.append(0x80)   # append a single '1' bit
    while len(message) % 64 != 56:
        message.append(0x00)  # append zeros until length is 64 bits less than a multiple of 512
    message += struct.pack('>Q', ml)  # append ml as 64-bit big-endian integer

    # Process each 512-bit (64 byte) chunk
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

        if( debug_state ):
            print(f"\t{offset/64}: {[hex(a) for a in H]}")

    if( debug_state ):
        print(f"FNL\t{offset/64}: {[hex(a) for a in H]}")

    # Produce the final hash value (big-endian)
    hash_hex = '{:08x}{:08x}{:08x}{:08x}{:08x}'.format(*H)
    return bytes.fromhex(hash_hex)

def sha1_keyed_mac( message:bytes, key:bytes ):
    pt = bytearray(key)
    pt.extend(message)
    return sha1_hash(pt)
    
def sha1_keyed_mac_validate( message:bytes, key:bytes, expected:bytes ):
    calculated = sha1_keyed_mac( message, key )
    if( calculated == expected ):
        return True
    return False

def sha1_hmac( message:bytes, key:bytes ):
    blocksize = 64
    ipad = bytes([0x36] * blocksize)
    opad = bytes([0x5c] * blocksize)

    # if key is larger than blocksize, hash it.
    if( len(key) > blocksize ):
        hmac_key = bytearray(sha1_hash( key ))
    else:
        hmac_key = bytearray(key)

    # zero pad key to blocksize
    while len(hmac_key) < blocksize:
        hmac_key.append(0x00)

    # HMAC Pass-1
    r1_data = bytearray([b1 ^ b2 for b1, b2 in zip( hmac_key, ipad )])
    r1_data.extend( message )
    r1_result = sha1_hash( r1_data )

    # HMAC Pass-2
    r2_data = bytearray([b1 ^ b2 for b1, b2 in zip( hmac_key, opad )])
    r2_data.extend( r1_result )
    
    return sha1_hash(r2_data)

def sha1_recover_state( sha1hash ):
    hexhash = sha1hash.hex()
    a = int(hexhash[0:8],16)
    b = int(hexhash[8:16],16)
    c = int(hexhash[16:24],16)
    d = int(hexhash[24:32],16)
    e = int(hexhash[32:40],16)
    return (a,b,c,d,e)

def sha1_generate_padding( message_length ):
    ml = message_length * 8 
    dummymsg = bytearray(random.randbytes(message_length))
    dummymsg.append(0x80)   
    while len(dummymsg) % 64 != 56:
        dummymsg.append(0x00)  
    dummymsg += struct.pack('>Q', ml)  
    return bytes(dummymsg[message_length:])

def sha1_run_test_vector( input, expected ):
    output = sha1_hash(input,debug_state=False).hex()
    print(f"{"Success" if output == expected else "Failure"} --- sha1({input}): '{output}', expected: '{expected}' ")
    assert output == expected

def sha1_hmac_run_test_vector( input, key, expected ):
    output = sha1_hmac(input,key).hex()
    print(f"{"Success" if output == expected else "Failure"} --- hmac-sha1({input}): '{output}', expected: '{expected}' ")
    assert output == expected


if __name__ == "__main__":
    sha1_run_test_vector( b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709" )
    sha1_run_test_vector( b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq","84983e441c3bd26ebaae4aa1f95129e5e54670f1" )
    sha1_run_test_vector( b"abc","a9993e364706816aba3e25717850c26c9cd0d89d" )

    sha1_hmac_run_test_vector( b"The quick brown fox jumps over the lazy dog", b"key", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9" )