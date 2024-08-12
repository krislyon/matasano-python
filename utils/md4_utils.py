import struct
import random


def md4_hash_set_state( message, STATE_A=0x67452301, STATE_B=0xefcdab89, STATE_C=0x98badcfe, STATE_D=0x10325476, forced_length=False, debug_state=False ):

    def md4_pad( message, forced_length=False ):
        padded = bytearray(message)
        if( forced_length != False ):
            ml = forced_length * 8
            print(f'Forcing Length: {forced_length}')
        else:
            ml = len(message) * 8 
        padded.append(0x80)   
        while len(padded) % 64 != 56:
            padded.append(0x00)  
        padded += struct.pack('<Q', ml)
        return bytes(padded)    

    def md4_F(x,y,z):
        return (x & y) | (~x & z)

    def md4_G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def md4_H(x, y, z):
        return x ^ y ^ z    

    def md4_rotleft(x,n):
        return ((x << n) & 0xFFFFFFFF) | (x >> (32-n))

    def md4_decode(raw):
        block = list( struct.unpack("<16I", raw) + (None,) * (80-16) )
        return block

    # Process the Hash
    H = [STATE_A, STATE_B, STATE_C, STATE_D]
    padded = md4_pad(message,forced_length)

    # Process each 512-bit (64 byte) chunk
    for offset in range(0, len(padded), 64):
        block = md4_decode( padded[offset:offset + 64] )

        # Round 0
        AA = H[0]
        BB = H[1]
        CC = H[2]
        DD = H[3]

        if( debug_state ):
            print(f"Block\t{["0x{:08x}".format(block[a]) for a in range(0,4)]}" ) 
            print(f"\t{["0x{:08x}".format(block[a]) for a in range(4,8)]}" ) 
            print(f"\t{["0x{:08x}".format(block[a]) for a in range(8,12)]}" ) 
            print(f"\t{["0x{:08x}".format(block[a]) for a in range(12,16)]}" ) 
            print()
            print(f"R0\t{[hex(a) for a in H]}")

        # Round 1
        H[0] = md4_rotleft(( H[0] + md4_F(H[1], H[2], H[3]) + block[0])  % 0x100000000, 3)
        H[3] = md4_rotleft(( H[3] + md4_F(H[0], H[1], H[2]) + block[1])  % 0x100000000, 7) 
        H[2] = md4_rotleft(( H[2] + md4_F(H[3], H[0], H[1]) + block[2])  % 0x100000000, 11) 
        H[1] = md4_rotleft(( H[1] + md4_F(H[2], H[3], H[0]) + block[3])  % 0x100000000, 19) 
        H[0] = md4_rotleft(( H[0] + md4_F(H[1], H[2], H[3]) + block[4])  % 0x100000000, 3)
        H[3] = md4_rotleft(( H[3] + md4_F(H[0], H[1], H[2]) + block[5])  % 0x100000000, 7) 
        H[2] = md4_rotleft(( H[2] + md4_F(H[3], H[0], H[1]) + block[6])  % 0x100000000, 11) 
        H[1] = md4_rotleft(( H[1] + md4_F(H[2], H[3], H[0]) + block[7])  % 0x100000000, 19) 
        H[0] = md4_rotleft(( H[0] + md4_F(H[1], H[2], H[3]) + block[8])  % 0x100000000, 3)
        H[3] = md4_rotleft(( H[3] + md4_F(H[0], H[1], H[2]) + block[9])  % 0x100000000, 7) 
        H[2] = md4_rotleft(( H[2] + md4_F(H[3], H[0], H[1]) + block[10]) % 0x100000000, 11) 
        H[1] = md4_rotleft(( H[1] + md4_F(H[2], H[3], H[0]) + block[11]) % 0x100000000, 19) 
        H[0] = md4_rotleft(( H[0] + md4_F(H[1], H[2], H[3]) + block[12]) % 0x100000000, 3)
        H[3] = md4_rotleft(( H[3] + md4_F(H[0], H[1], H[2]) + block[13]) % 0x100000000, 7) 
        H[2] = md4_rotleft(( H[2] + md4_F(H[3], H[0], H[1]) + block[14]) % 0x100000000, 11) 
        H[1] = md4_rotleft(( H[1] + md4_F(H[2], H[3], H[0]) + block[15]) % 0x100000000, 19) 

        if( debug_state ):
            print(f"R1\t{[hex(a) for a in H]}")

        # Round 2
        H[0] = md4_rotleft((H[0] + md4_G(H[1], H[2], H[3]) + block[0]  + 0x5A827999) % 0x100000000, 3 )
        H[3] = md4_rotleft((H[3] + md4_G(H[0], H[1], H[2]) + block[4]  + 0x5A827999) % 0x100000000, 5 )
        H[2] = md4_rotleft((H[2] + md4_G(H[3], H[0], H[1]) + block[8]  + 0x5A827999) % 0x100000000, 9 )
        H[1] = md4_rotleft((H[1] + md4_G(H[2], H[3], H[0]) + block[12] + 0x5A827999) % 0x100000000, 13 )
        H[0] = md4_rotleft((H[0] + md4_G(H[1], H[2], H[3]) + block[1]  + 0x5A827999) % 0x100000000, 3 )
        H[3] = md4_rotleft((H[3] + md4_G(H[0], H[1], H[2]) + block[5]  + 0x5A827999) % 0x100000000, 5 )
        H[2] = md4_rotleft((H[2] + md4_G(H[3], H[0], H[1]) + block[9]  + 0x5A827999) % 0x100000000, 9 )
        H[1] = md4_rotleft((H[1] + md4_G(H[2], H[3], H[0]) + block[13] + 0x5A827999) % 0x100000000, 13 )
        H[0] = md4_rotleft((H[0] + md4_G(H[1], H[2], H[3]) + block[2]  + 0x5A827999) % 0x100000000, 3 )
        H[3] = md4_rotleft((H[3] + md4_G(H[0], H[1], H[2]) + block[6]  + 0x5A827999) % 0x100000000, 5 )
        H[2] = md4_rotleft((H[2] + md4_G(H[3], H[0], H[1]) + block[10] + 0x5A827999) % 0x100000000, 9 )
        H[1] = md4_rotleft((H[1] + md4_G(H[2], H[3], H[0]) + block[14] + 0x5A827999) % 0x100000000, 13 )
        H[0] = md4_rotleft((H[0] + md4_G(H[1], H[2], H[3]) + block[3]  + 0x5A827999) % 0x100000000, 3 )
        H[3] = md4_rotleft((H[3] + md4_G(H[0], H[1], H[2]) + block[7]  + 0x5A827999) % 0x100000000, 5 )
        H[2] = md4_rotleft((H[2] + md4_G(H[3], H[0], H[1]) + block[11] + 0x5A827999) % 0x100000000, 9 )
        H[1] = md4_rotleft((H[1] + md4_G(H[2], H[3], H[0]) + block[15] + 0x5A827999) % 0x100000000, 13 )

        if( debug_state ):
            print(f"R2\t{[hex(a) for a in H]}")

        # Round 3
        H[0]=md4_rotleft((H[0] + md4_H(H[1], H[2], H[3]) + block[0]  + 0x6ED9EBA1) % 0x100000000, 3 )
        H[3]=md4_rotleft((H[3] + md4_H(H[0], H[1], H[2]) + block[8]  + 0x6ED9EBA1) % 0x100000000, 9 )
        H[2]=md4_rotleft((H[2] + md4_H(H[3], H[0], H[1]) + block[4]  + 0x6ED9EBA1) % 0x100000000, 11 )
        H[1]=md4_rotleft((H[1] + md4_H(H[2], H[3], H[0]) + block[12] + 0x6ED9EBA1) % 0x100000000, 15 )
        H[0]=md4_rotleft((H[0] + md4_H(H[1], H[2], H[3]) + block[2]  + 0x6ED9EBA1) % 0x100000000, 3 )
        H[3]=md4_rotleft((H[3] + md4_H(H[0], H[1], H[2]) + block[10] + 0x6ED9EBA1) % 0x100000000, 9 )
        H[2]=md4_rotleft((H[2] + md4_H(H[3], H[0], H[1]) + block[6]  + 0x6ED9EBA1) % 0x100000000, 11 )
        H[1]=md4_rotleft((H[1] + md4_H(H[2], H[3], H[0]) + block[14] + 0x6ED9EBA1) % 0x100000000, 15 )
        H[0]=md4_rotleft((H[0] + md4_H(H[1], H[2], H[3]) + block[1]  + 0x6ED9EBA1) % 0x100000000, 3 )
        H[3]=md4_rotleft((H[3] + md4_H(H[0], H[1], H[2]) + block[9]  + 0x6ED9EBA1) % 0x100000000, 9 )
        H[2]=md4_rotleft((H[2] + md4_H(H[3], H[0], H[1]) + block[5]  + 0x6ED9EBA1) % 0x100000000, 11 )
        H[1]=md4_rotleft((H[1] + md4_H(H[2], H[3], H[0]) + block[13] + 0x6ED9EBA1) % 0x100000000, 15 )
        H[0]=md4_rotleft((H[0] + md4_H(H[1], H[2], H[3]) + block[3]  + 0x6ED9EBA1) % 0x100000000, 3 )
        H[3]=md4_rotleft((H[3] + md4_H(H[0], H[1], H[2]) + block[11] + 0x6ED9EBA1) % 0x100000000, 9 )
        H[2]=md4_rotleft((H[2] + md4_H(H[3], H[0], H[1]) + block[7]  + 0x6ED9EBA1) % 0x100000000, 11 )
        H[1]=md4_rotleft((H[1] + md4_H(H[2], H[3], H[0]) + block[15] + 0x6ED9EBA1) % 0x100000000, 15 )

        if( debug_state ):
            print(f"R3\t{[hex(a) for a in H]}")

        # Add back to initial state
        H[0] = ( H[0] + AA ) % 0x100000000
        H[1] = ( H[1] + BB ) % 0x100000000
        H[2] = ( H[2] + CC ) % 0x100000000
        H[3] = ( H[3] + DD ) % 0x100000000

    if( debug_state ):
        print(f"FNL\t{[hex(a) for a in H]}")

    out = struct.pack("<4I", *H)
    return bytes(out)

def md4_hash(message, debug_state=False):
    return md4_hash_set_state( message, debug_state=debug_state )

def md4_keyed_mac( message:bytes, key:bytes, debug_state=False ):
    pt = bytearray(key)
    pt.extend(message)
    return md4_hash(pt,debug_state=debug_state)

def md4_keyed_mac_validate( message:bytes, key:bytes, expected:bytes ):
    calculated = md4_keyed_mac( message, key )
    if( calculated == expected ):
        return True
    return False

def md4_recover_state( md4hash ):
    BEdata = struct.unpack(">4I", md4hash )
    LEdata = struct.pack("<4I", *BEdata )   
    hexhash = LEdata.hex()
    a = int(hexhash[0:8],16)
    b = int(hexhash[8:16],16)
    c = int(hexhash[16:24],16)
    d = int(hexhash[24:32],16)

    print( hexhash[0:8], hexhash[8:16], hexhash[16:24], hexhash[24:32] )

    return (a,b,c,d)

def md4_generate_padding( message_length ):
    ml = message_length * 8  
    dummymsg = bytearray(random.randbytes(message_length))
    dummymsg.append(0x80)   
    while len(dummymsg) % 64 != 56:
        dummymsg.append(0x00)  
    dummymsg += struct.pack('<Q', ml) 
    return bytes(dummymsg[message_length:])

if __name__ == "__main__":

    def md4_run_test_vector( input, expected ):
        output = md4_hash(input,debug_state=False).hex()
        print(f"{"Success" if output == expected else "Failure"} --- md4({input}): '{output}', expected: '{expected}' ")
        print()

    md4_run_test_vector( b"", "31d6cfe0d16ae931b73c59d7e0c089c0" )
    md4_run_test_vector( b"a","bde52cb31de33e46245e05fbdbd6fb24" )
    md4_run_test_vector( b"abc","a448017aaf21d8525fc10ae87aa6729d" )
    md4_run_test_vector( b"message digest","d9130a8164549fe818874806e1c7014b" )
    md4_run_test_vector( b"abcdefghijklmnopqrstuvwxyz","d79e1c308aa5bbcdeea8ed63df412da9" )