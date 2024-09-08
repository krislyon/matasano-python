# Matasano Crypto Challenges
# Set 3, Challenge 17 - The CBC Padding Oracle
#
import sys
import base64
import os
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from block_utils import pkcs7_pad, pkcs7_unpad, encrypt_aes_manual_cbc, decrypt_aes_manual_cbc

def load_base64_data( filename: str ) -> bytes:
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        data = [base64.b64decode(line) for line in file.readlines()]
        return data

aeskey = random.randbytes(16)
iv = random.randbytes(16)
plaintexts = load_base64_data('s3c17.dat')

def get_ciphertext(pt_idx):
    line = plaintexts[pt_idx]
    pt = pkcs7_pad(line)
    ct = encrypt_aes_manual_cbc( pt, aeskey, iv )
    return ct

def padding_oracle( ciphertext, attack_iv ):
    pt = decrypt_aes_manual_cbc( ciphertext, aeskey, attack_iv )
    try:
        pkcs7_unpad( pt, True )
        return True
    except:
        return False



print('Matasano Crypto Challenges')
print('Set 3, Challenge 17 - The CBC Padding Oracle')
print('--------------------------------------------')

for text in range(0,len(plaintexts)):
    ct = get_ciphertext(text)
    
    ctlength = len(ct)
    blocksize = 16
    blockcount = int(ctlength/blocksize)

    # print("Ciphertext Length:\t" + str(ctlength))
    # print("Blocksize:\t\t" + str(blocksize))
    # print("Blockcount:\t\t" + str(blockcount))
    
    recovered_blocks = []
    # Attack each block independently, starting at the end of the ciphertext
    for attack_block_idx in range(blockcount-1,-1,-1):
        recovered_block = bytearray()
        corrupt_block_idx = attack_block_idx-1
        internal_aes_state = bytearray(bytes.fromhex("00000000000000000000000000000000")) 

        # attack last block of ciphertext byte by byte, corrupt previous block byte by byte
        for expected_pad in range(1,blocksize+1):
            modified_iv = bytearray(iv)
            modified_ct = bytearray(ct[0:(attack_block_idx+1)*blocksize])
        
            byte_idx_in_block = (blocksize-expected_pad)

            # print("\nProcessing Next Byte:")
            # print("attack_block_idx:" + str(attack_block_idx) + ",\tcorrupt_block_idx:" + str(corrupt_block_idx) + ",\tbyte_idx_in_block: " + str(byte_idx_in_block) + ",\texpected pad: " + expected_pad.to_bytes().hex() )
            # print("--------------------------------------------------------------------------------------------------")

            # store the original ciphertext byte
            if corrupt_block_idx >= 0:
                orig_ct_byte = ct[(blocksize*corrupt_block_idx)+byte_idx_in_block]
            else:
                orig_ct_byte = iv[byte_idx_in_block]

            # bruteforce our target byte ()
            for byte_guess in range(257):

                if byte_guess == 256:
                    print('\nNo Valid Pad Found')
                    break

                if corrupt_block_idx >= 0:
                    for i in range(blocksize):
                        modified_ct[(corrupt_block_idx*blocksize)+i] = internal_aes_state[i] ^ expected_pad
                    modified_ct[(corrupt_block_idx*blocksize)+byte_idx_in_block] = byte_guess
                else:
                    for i in range(blocksize):
                        modified_iv[i] = internal_aes_state[i] ^ expected_pad
                    modified_iv[byte_idx_in_block] = byte_guess

                if padding_oracle( modified_ct, modified_iv ):
                    #print('\nValid Pad Detected: ' + byte_guess.to_bytes().hex() )
                    #print('Modified CT: ' + bytes(modified_ct).hex() )
                    #print('IV: ' + bytes(modified_iv).hex() )
                    pt_byte = byte_guess ^ orig_ct_byte ^ expected_pad
                    internal_aes_state[byte_idx_in_block] = pt_byte ^ orig_ct_byte
                    recovered_block.insert(0,pt_byte)
                    #print('internal_aes_state: ' + bytes(internal_aes_state).hex() )
                    #print( recovered_block )
                    break

        try:
            recovered_blocks.append( pkcs7_unpad(recovered_block,True) )
        except:
            recovered_blocks.append( recovered_block )

    result = bytearray()
    for idx in range(len(recovered_blocks)-1,-1,-1):
        result.extend( recovered_blocks[idx] )
    
    print( result.decode("utf-8") )
    



    
    
    