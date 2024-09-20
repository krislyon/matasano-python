# Matasano Crypto Challenges
# Set 2, Challenge 14 - Byte-at-a-time ECB decryption (Harder)
#
import sys
import base64
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from typing import Dict
from block_utils import pkcs7_pad, pkcs7_unpad, encrypt_aes_ecb, detect_ecb, detect_blockcipher_metrics, detect_duplicate_blocks

def load_base64_data( filename: str ) -> bytes:
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
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

def create_ecb_codebook( junk_offset:bytes, junk_blocks:int, prefix:bytes, blocksize:int=16 ) -> Dict[str,str]:
    assert len(prefix) == (blocksize-1), "Creating codebook with incorrect prefix length, must be blocksize-1, got: " + str(len(prefix)) 
    ecb_codebook = {}
    #print( prefix.hex() )
    #print( len(prefix) )

    for i in range(256):
        pt = bytearray(junk_offset)
        pt.extend(prefix)
        pt.append(i)
        ct = oracle( bytes(pt) )
        block = ct[junk_blocks*blocksize:(junk_blocks+1)*blocksize]
        # print( pt.hex() )
        # print( ct.hex() ) 
        #print(block.hex() + " : " + bytes(pt[-blocksize:]).hex())
        ecb_codebook[block.hex()] = bytes(pt[-blocksize:]).hex()
    return ecb_codebook

def detect_length_random_bytes( blocksize:int=16 ):
    # Count the number of bytes we had to add to force a duplicate block
    # (z) - random bytes, (t) - target bytes, using blocksize = 8 for readability here.
    # case1: random bytes are not-block aligned  zzzzAAAA AAAAAAAA AAAAAAAA tttttttt
    # case2: random bytes are block-aligned      zzzzzzzz AAAAAAAA AAAAAAAA tttttttt
    # randomByteLength = (lastBlockMatchStart * blocksize) - (count - blocksize);
    for count in range(blocksize*2,blocksize*3):
        known_pt = bytes('A' * count,'utf-8')
        ct = oracle( known_pt )
        (dup_block_found,dup_block_num) = detect_duplicate_blocks(ct)

        if dup_block_found:
            return (dup_block_num * blocksize) - (count-2*blocksize)   
   
def recover_block( junk_offset:int, junk_blocks:int, blocknum:int, recovered_data:bytes, blocksize:int, recovery_target:int=0 ):
    recovered_block = bytearray()

    for byte_num in range(1,blocksize+1):

        if recovery_target != 0:
            if len(recovered_data) + len(recovered_block) == recovery_target:
                print('**Recovery Target Reached, breaking and padding.')
                break

        # prefix our knowndata
        if len(recovered_data)==0:
            # Account for our translation padding in first blocks
            prefix = bytearray( 'A' * (blocksize-byte_num),'utf-8')
            prefix.extend(recovered_block)
            codebook = create_ecb_codebook( junk_offset, junk_blocks, prefix )
        else:
            # Need to use known data
            rdatalen = len(recovered_data)
            # print( str(rdatalen-(blocksize-byte_num)) + ' : ' + str(rdatalen) )
            prefix = bytearray( recovered_data[rdatalen-(blocksize-byte_num):rdatalen] )
            prefix.extend(recovered_block)
            # print( 'bk: ' + recovered_block.hex() )
            # print( 'px: ' + prefix.hex() )
            codebook = create_ecb_codebook( junk_offset, junk_blocks, prefix )

        # translate target byte to the end of the block
        data = bytearray('o' * junk_offset, 'utf-8')
        data.extend( bytes('A' * (blocksize-byte_num),'utf-8') )
        ct = oracle( data )

        # look up the plaintext for the block, recovering the byte
        block = ct[blocknum*blocksize:((blocknum+1)*blocksize)]
        #print( 'ct: ' + block.hex() )
        #print( 're: ' + recovered_block.hex() )
        pt = bytes.fromhex( codebook[block.hex()] )
        #print( 'pt: ' + codebook[block.hex()] )

        # store the recovered byte
        recovered_block.append(pt[15]) 

    if recovery_target != 0 and len(recovered_block) != blocksize:
        pad = blocksize - len(recovered_block)
        for i in range(pad):
            recovered_block.append(pad)

    return bytes(recovered_block)

def run_challenge_14():
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 14 - Byte-at-a-time ECB decryption (Harder)')
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
    print('ECB Detected:\t\t' + str(using_ecb))
    print('')
    # Detect Random Byte Length
    rand_byte_length = detect_length_random_bytes()
    print('Random Byte Count Detected:\t' + str(rand_byte_length) )

    recv_length = pt_length - rand_byte_length
    print('Target Recovery Length:\t\t' + str(recv_length))


    # Determine how many junk bytes we need to add to complete the first random blocks.
    junk_count = 0
    while (rand_byte_length + junk_count) % blocksize != 0:
        junk_count += 1
    print('Junk Byte Count:\t\t' + str(junk_count) )
    junk_blocks = int( (rand_byte_length + junk_count) / blocksize )
    print('Junk Blocks (skip):\t\t' + str(junk_blocks) )

    # Decrypt with Attack
    recovered_data = bytearray()  
    for blocknum in range( junk_blocks, block_count ):
        result = recover_block( junk_count, junk_blocks, blocknum, bytes(recovered_data), blocksize, recv_length )
        recovered_data.extend( result )
        print('Block ' + str(blocknum) + ' Complete: \t' + result.hex() )

    print()
    result = pkcs7_unpad( recovered_data ).decode('utf-8')
    print( result )
    return result

if __name__ == '__main__':
    run_challenge_14()
