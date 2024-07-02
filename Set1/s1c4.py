#
# S1C4.py
#

hex_data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
xor_enc_data = bytes.fromhex( hex_data )

def create_xor_key(len,val):
    return bytes([val] * len)

def fixed_xor( buf1, buf2 ):
    return bytes([b1 ^ b2 for b1, b2 in zip( buf1, buf2)])

def readable_ascii_score( buf ):
    score = 0
    for byte in buf:
        if( ((byte >= 32) and (byte <= 41)) or ((byte >= 65) and (byte <= 90)) or ((byte >= 48) and (byte <= 57)) or ((byte >= 97) and (byte <= 122)) ):
            score = score + 1
    return score / len(buf)


def load_data( filename ):
    with open( filename, 'r') as file:
        # Read all lines into a list
        lines = file.readlines()
        return lines


if __name__ == '__main__':

    filedata = load_data('s1c4.dat')
    max_score = 0
    max_key = 0
    max_result = ""

    for line in filedata:    
        xor_enc_data = bytes.fromhex(line)
        for i in range(256):
            key_guess = create_xor_key( len(xor_enc_data), i )
            result = fixed_xor( xor_enc_data, key_guess )

            score = readable_ascii_score( result )
            if( score > max_score ):
                max_score = score
                max_key = i
                max_result = result

    print( str(max_key) + " : " + str( max_score ) + " : " + str(max_result) )

