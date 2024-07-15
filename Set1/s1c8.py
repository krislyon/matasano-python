# Matasano Crypto Challenges
# Set 1, Challenge 8 - Detect AES in ECB mode
#
import base64

def load_ciphertexts( filename:str ) -> bytes:
    with open( filename, 'r') as file:
        # Read all lines into a list
        lines = file.readlines()
        result = [bytes.fromhex(l) for l in lines]
        return result

def detect_ecb( ciphertext:bytes, blocksize:int=16 ) -> bool:
    bdict = {}
    blocks = [ciphertext[(i)*blocksize:(i+1)*blocksize] for i in range(0, int(len(ciphertext)/blocksize)-1 ) ]
    
    for block in blocks:
        if block.hex() in bdict:
            return True
        else:
            bdict[block.hex()] = 1

    return False


if __name__ == '__main__':
    ciphertexts = load_ciphertexts('s1c8.dat')

    for ciphertext in ciphertexts:
        result = detect_ecb( ciphertext )
        if result:
            print("ECB Mode detected.")
            print("Duplicate blocks detected in ciphertext:\n" + str( ciphertext.hex() ))