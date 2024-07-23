# Matasano Crypto Challenges
# Set 2, Challenge 12 - Byte-at-a-time ECB decryption (Simple)
#
import sys
import base64
import random
from typing import Dict, Tuple
sys.path.append('../utils')
from block_utils import pkcs7_pad, encrypt_aes_ecb, detect_ecb,detect_blockcipher_metrics
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

print('Matasano Crypto Challenges')
print('Set 2, Challenge 12 - Byte-at-a-time ECB decryption (Simple)')
print('------------------------------------------')

# Calculate Message Metrics
(blocksize, block_count, ctlength, pad_length, pt_length) = detect_blockcipher_metrics( oracle )
print('Blocksize:\t\t' + str(blocksize))
print('Block Count:\t\t' + str(block_count))
print('Ciphertext Length:\t' + str(ctlength))
print('Padding:\t\t' + str(pad_length))
print('Plaintext Length:\t' + str(pt_length))

# Detect ECB - we know the blocksize, we can force a block repeat with the prefix
prefix = bytes( 'A' * (blocksize*3) ,'utf-8')
using_ecb = detect_ecb( oracle( prefix ) )
print('ECB Detected: ' + str(using_ecb))

# Decrypt with Attack
recovered_data = bytearray()
for blocknum in range( 9 ):
    print('\nStarting Block: ' + str(blocknum) )
    print('----------------------------------------------')
    result = recover_block( blocknum, bytes(recovered_data), pt_length )
    recovered_data.extend( result )
    print('Block ' + str(blocknum) + ' Complete: ' + result.hex() + '\n' )

print( recovered_data.decode('utf-8'))

