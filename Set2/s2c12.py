# Matasano Crypto Challenges
# Set 2, Challenge 12 - Byte-at-a-time ECB decryption (Simple)
#
import sys
import base64
import random
from typing import Dict, Tuple
sys.path.append('../utils')
from block_utils import pkcs7_pad, encrypt_aes_ecb, detect_ecb
from text_utils import hexdump

def load_base64_data( filename: str ) -> bytes:
    with open( filename, 'r') as file:
        data = base64.b64decode( file.read() )
        return data

aeskey = random.randbytes(16)
secretdata = load_base64_data('s2c12.dat')

def oracle( attacker_controlled: bytes ) -> bytes:
    data = bytearray()
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

def detect_pad_length() -> Tuple[int,int,int]:
    ctlength = len( oracle( bytes() ) )
    prefix = ''
    ctlength1 = ctlength
    while(  ctlength1 == ctlength ):
        prefix += 'A'
        ctlength1 = len( oracle( bytes(prefix,'utf-8') ) )

    pad_length = len(prefix) - 1
    return ( ctlength, pad_length, ctlength-pad_length )

def create_ecb_codebook( prefix:bytes, blocksize:int=16 ) -> Dict[str,str]:
    assert len(prefix) == (blocksize-1), "Creating codebook with incorrect prefix length, must be blocksize-1, got: " + str(len(prefix)) 
    ecb_codebook = {}

    for i in range(256):
        pt = bytearray(prefix)
        pt.append(i)
        ct = oracle( bytes(pt) )
        block = ct[0:blocksize]
        #print(block.hex() + " : " + bytes(pt).hex())
        ecb_codebook[block.hex()] = bytes(pt).hex()
    return ecb_codebook

def recover_block( blocknum:int, recovered_data:bytes, recovery_target:int=0 ):
    recovered_block = bytearray()

    for byte_num in range(1,blocksize+1):

        if recovery_target != 0:
            if len(recovered_data) + len(recovered_block) == recovery_target:
                print('Recovery Target Reached, breaking and padding.')
                break

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

        # offset target byte to the end of the block
        offset_padding = bytes('A' * (blocksize-byte_num),'utf-8')
        ct = oracle( offset_padding )

        # look up the plaintext for the block, recovering the byte
        block = ct[blocknum*blocksize:((blocknum+1)*blocksize)]
        print( 'ct: ' + block.hex() )
        print( 're: ' + recovered_block.hex() )
        pt = bytes.fromhex( codebook[block.hex()] )
        print( 'pt: ' + codebook[block.hex()] )

        # store the recovered byte
        recovered_block.append(pt[15]) 

    if recovery_target != 0 and len(recovered_block) != blocksize:
        pad = blocksize - len(recovered_block)
        for i in range(pad):
            recovered_block.append(pad)

    return bytes(recovered_block)

if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 12 - Byte-at-a-time ECB decryption (Simple)')
    print('------------------------------------------')

    # Determine Blocksize - observe changes in ciphertext length to determine blocksize
    blocksize = detect_blocksize()
    print('Detected Blocksize: ' + str(blocksize))
    # if len(secretdata) % blocksize == 0:
    #     print('Secret data is blocksize aligned.')
    # else:
    #     print('Secret data is NOT blocksize aligned.')
    #secretdata = pkcs7_pad( secretdata )

    # Detect ECB - we know the blocksize, we can force a block repeat with the prefix
    prefix = bytes( 'A' * (blocksize*3) ,'utf-8')
    using_ecb = detect_ecb( oracle( prefix ) )
    print('ECB Detected: ' + str(using_ecb))

    # Calculate block count with full pad.
    prefix = bytes('A' * blocksize, 'utf-8')
    ct = oracle( prefix )
    blockcount = int(len(ct) / blocksize)
    print('Blockcount: ' + str(blockcount))

    # Calculate Message Lengths
    (ctlength, padlength, msglength) = detect_pad_length()
    print('Ciphertext Length:\t' + str(ctlength))
    print('Padding:\t\t' + str(padlength))
    print('Message Length:\t\t' + str(msglength))

    # Decrypt with Attack
    recovered_data = bytearray()
    for blocknum in range( 9 ):
        print('\nStarting Block: ' + str(blocknum) )
        print('----------------------------------------------')
        result = recover_block( blocknum, bytes(recovered_data), msglength )
        recovered_data.extend( result )
        print('Block ' + str(blocknum) + ' Complete: ' + result.hex() + '\n' )

    print( recovered_data.decode('utf-8'))

