# Matasano Crypto Challenges
# Set 1, Challenge 6 - Break repeating-key XOR
#
import base64


MAX_KEY_SIZE = 40


def bitwise_hamming_distance(s1, s2):
    if len(s1) != len(s2):
        raise ValueError("Strings must be of the same length")
    
    # Calculate the bitwise hamming distance
    distance = 0
    for c1, c2 in zip(s1, s2):
        # XOR the characters and count the number of 1s in the result
        distance += bin(c1 ^ c2).count('1')

    return distance / len(s1)


def calculate_xor_keysize( max, ciphertext ):
    mindist = (MAX_KEY_SIZE + 1)
    minsize = 0

    for ksize in range( 2, max ):
        strA = ciphertext[0:ksize]
        strB = ciphertext[ksize:2*ksize]
        dist = bitwise_hamming_distance(strA,strB)
        #print( "KSize: " + str(ksize) + ", dist: " + str(dist) )

        if dist < mindist:
            mindist = dist
            minsize = ksize

    #print( minsize )
    return minsize


def load_data( filename ):
    with open( filename, 'r') as file:
        data = base64.b64decode( file.read() )
        return data


def transpose_bytes( blocks, data ):
    count = 0
    for b in data:
        



if __name__ == '__main__':
    ciphertext = load_data('s1c6.dat')
    keySize = calculate_xor_keysize( MAX_KEY_SIZE, ciphertext )
    print("Keysize Guess: " + str(keySize) )


    