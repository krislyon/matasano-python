# Matasano Crypto Challenges
# Set 2, Challenge 14 - Byte-at-a-time ECB decryption (Harder)
#
import sys
import base64
import random
from typing import Dict
sys.path.append('../utils')
from block_utils import pkcs7_pad, encrypt_aes_ecb, detect_ecb, split_blocks
from text_utils import hexdump

def load_base64_data( filename: str ) -> bytes:
    with open( filename, 'r') as file:
        data = base64.b64decode( file.read() )
        return data

aeskey = random.randbytes(16)
random_prefix = random.randbytes( random.randint(0,128) )
secretdata = load_base64_data('s2c12.dat')


def oracle( attacker_controlled: bytes ) -> bytes:
    data = bytearray()
    data.extend( random_prefix )
    data.extend( attacker_controlled )
    data.extend( secretdata )
    data = pkcs7_pad(data)
    ct = encrypt_aes_ecb( data, aeskey )
    return ct

def detect_blocksize():
    # find first ciphertext blocksize increase (full padding)
    ctlength = len( oracle( bytes() ) )
    prefix = ''
    ctlength1 = ctlength
    while(  ctlength1 == ctlength ):
        prefix += 'A'
        ctlength1 = len( oracle( bytes(prefix,'utf-8') ) )

    # find second ciphertext blocksize increase
    ctlength2 = ctlength1
    while( ctlength1 == ctlength2 ):
        prefix += 'B'
        ctlength2 = len( oracle( bytes(prefix,'utf-8') ) )

    return ( ctlength2 - ctlength1 )

def create_ecb_codebook( prefix:bytes, blocksize:int=16 ) -> Dict[str,str]:
    assert len(prefix) == (blocksize-1), "Creating codebook with incorrect prefix length, must be blocksize-1, got: " + str(len(prefix)) 
    ecb_codebook = {}
    #print( prefix.hex() )
    #print( len(prefix) )

    for i in range(256):
        pt = bytearray(prefix)
        pt.append(i)
        ct = oracle( bytes(pt) )
        block = ct[0:blocksize]
        #print( pt.hex() )
        #print( ct.hex() ) 
        #print(block.hex() + " : " + bytes(pt).hex())
        ecb_codebook[block.hex()] = bytes(pt).hex()
    return ecb_codebook

def detect_length_random_bytes():
    # Count the number of bytes we had to add to force a duplicate block
    # (z) - random bytes, (t) - target bytes, using blocksize = 8 for readability here.
    # case1: random bytes are not-block aligned  zzzzAAAA AAAAAAAA AAAAAAAA tttttttt
    # case2: random bytes are block-aligned      zzzzzzzz AAAAAAAA AAAAAAAA tttttttt
    # randomByteLength = (lastBlockMatchStart * blocksize) - (count - blocksize);
    for count in range(blocksize*2,blocksize*3):
        prefix = bytes('A' * count,'utf-8')
        ct = oracle( prefix )
        blocks = split_blocks( ct )
        for block1 in blocks:
            blockcount = 0
            for block2 in blocks:
                if( block1 == block2 ):
                    blockcount += 1
            if blockcount > 1:
                print('Count: ' + str(count))
                return count

        assert True, 'shouldnt get here'

def recover_block( blocknum, recovered_data, secretdata, key ):
    recovered_block = bytearray()

    for byte_num in range(1,blocksize+1):

        # prefix our knowndata
        if blocknum == 0:
            # Account for our translation padding in first blocks
            prefix = bytearray( 'A' * (blocksize-byte_num),'utf-8')
            prefix.extend(recovered_block)
            codebook = create_ecb_codebook( prefix )
        else:
            # Need to use known data
            rdatalen = len(recovered_data)
            # print( str(rdatalen-(blocksize-byte_num)) + ' : ' + str(rdatalen) )
            prefix = bytearray( recovered_data[rdatalen-(blocksize-byte_num):rdatalen] )
            prefix.extend(recovered_block)
            # print( 'bk: ' + recovered_block.hex() )
            # print( 'px: ' + prefix.hex() )
            codebook = create_ecb_codebook( prefix )

        # translate target byte to the end of the block
        translation_padding = bytes('A' * (blocksize-byte_num),'utf-8')
        ct = oracle( translation_padding )

        # look up the plaintext for the block, recovering the byte
        block = ct[blocknum*blocksize:((blocknum+1)*blocksize)]
        print( 'ct: ' + block.hex() )
        print( 're: ' + recovered_block.hex() )
        pt = bytes.fromhex( codebook[ block.hex() ] )
        print( 'pt: ' + codebook[block.hex()] )

        # store the recovered byte
        recovered_block.append(pt[15]) 


    assert len(recovered_block) == 16, "Off by one."
    return bytes(recovered_block)

if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 14 - Byte-at-a-time ECB decryption (Harder)')
    print('------------------------------------------')

    key = random.randbytes(16)
    secretdata = load_base64_data('s2c12.dat')

    # Determine Blocksize - observe changes in ciphertext length to determine blocksize
    blocksize = detect_blocksize()
    print('Detected Blocksize: ' + str(blocksize))


    # Detect ECB - we know the blocksize, we can force a block repeat with the prefix
    prefix = bytes( 'A' * (blocksize*3) ,'utf-8')
    using_ecb = detect_ecb( oracle( prefix ) )
    print('ECB Detected: ' + str(using_ecb))

    # Detect Random Byte Length
    rand_byte_length = detect_length_random_bytes()
    print('Random Byte Count Detected: ' + str(rand_byte_length) )

    # Decrypt with Attack
    # recovered_data = bytearray()
    # for blocknum in range( int(len(secretdata) / blocksize) ):
    #     result = recover_block( blocknum, bytes(recovered_data), secretdata, key)
    #     recovered_data.extend( result )
    #     print('Block ' + str(blocknum) + ' Complete: ' + result.hex() )

    # print( recovered_data.decode('utf-8'))

