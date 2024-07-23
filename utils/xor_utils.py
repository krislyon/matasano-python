import math
from typing import Tuple,Dict,Generator
from text_utils import *


MAX_KEY_SIZE = 40

def RepeatingKeyGenerator(keydata:bytes):
    keyLength = len(keydata)
    i=0
    while True:
        yield keydata[i]
        i = (i+1)%(keyLength)

def BufferGenerator(buffer:bytes) -> Generator[int,None,None]:
    i=0
    bufLength = len(buffer)
    while i<bufLength:
        yield buffer[i]
        i+=1
    raise ValueError('BufferGenerator exceeded buffer length: ' + str(bufLength) ) 

def create_xor_key(len:int, byte_value) -> bytes:
    return bytes([byte_value] * len)

def create_repeating_key_buffer( key_string:str, length:int ) -> bytes:
    key = bytearray( key_string,'utf-8')
    return [ key[i%3] for i in range(length) ]

def buffer_xor( buf1:bytes, buf2:bytes ) -> bytes:
    return bytes([b1 ^ b2 for b1, b2 in zip( buf1, buf2 )])

def repeating_key_xor( buf1:bytes, keyString:str ) -> bytes:
    return bytes([b1 ^ b2 for b1, b2 in zip(buf1, gen_repeating_string_keystream(keyString) )])

def transpose_data_blocks( data:bytes, blocksize:int ) -> list[bytes]: 
    datalen = len(data)
    nBlocks = (datalen/blocksize) + 1
    transposed_blocks = []
    for i in range(blocksize):
        block = []
        j=-1
        while( ((j+1)*blocksize)+i < datalen ):
            j+=1
            block.append( data[(j*blocksize)+i] )
        transposed_blocks.append( bytes(block) )
    return transposed_blocks

def calculate_xor_keysize( ciphertext:bytes, max_key_size:int=MAX_KEY_SIZE, debug:bool=False ) -> Tuple[int, Dict[int, float]]:
    mindist = (MAX_KEY_SIZE + 1)
    minsize = 0
    ksize_results = {}

    if debug:
        print( "Calculating XOR Key Size between 2 and " + str(max_key_size)  + " bytes.")

    for ksize in range( 2, max_key_size ):
        strA = ciphertext[0:ksize]
        strB = ciphertext[ksize:ksize*2]
        strC = ciphertext[ksize*2:ksize*3]
        strD = ciphertext[ksize*3:ksize*4]

        avgdist = ( bitwise_hamming_distance(strA,strB) + 
                    bitwise_hamming_distance(strA,strC) + 
                    bitwise_hamming_distance(strA,strD) + 
                    bitwise_hamming_distance(strB,strC) + 
                    bitwise_hamming_distance(strB,strD) + 
                    bitwise_hamming_distance(strC,strD))/6;

        ksize_results[ksize] = avgdist

        if debug:
            print( "\tCandidate Key Size: " + str(ksize) + ", dist: " + str(avgdist) )

        if avgdist < mindist:
            mindist = avgdist
            minsize = ksize

    if debug:
        print( "Probable Key Size: " + str(minsize) + ", dist: " + str(mindist) )

    return minsize, ksize_results

def recover_xor_key( transposed_data_blocks:list[bytes], debug:bool=False ) -> bytes:
    recovered_key = bytearray()
    for idx,block in enumerate(transposed_data_blocks):
        max_score = 0
        max_key = 0
        max_result = ""      
    
        for i in range(256):
            key_guess = create_xor_key( len(block), i )
            result = buffer_xor( block, key_guess )

            score = ascii_range_score( result )
            if( score > max_score ):
                max_score = score
                max_key = i
                max_result = result

        recovered_key.append( max_key )

        if debug:
            print( "Block: '" + str(idx) + "', key: '" + str(max_key) + "'" )
    
    result = bytes(recovered_key)
    if debug:
        print('Recovered Key: ' + str(result) )

    return result

def detect_diff_start( buf1:bytes, buf2:bytes ):
    idx = 0
    lb1 = len(buf1)
    lb2 = len(buf2)
    while( buf1[idx] == buf2[idx] and idx < lb1 and idx < lb2 ):
        idx += 1

    if( idx == lb1 or idx == lb2 ):
        return -1

    return idx

def detect_diff_end( buf1:bytes, buf2:bytes ):
    idx = 0
    lb1 = len(buf1)
    lb2 = len(buf2)
    while( buf1[idx] != buf2[idx] and idx < lb1 and idx < lb2 ):
        idx += 1

    if( idx == lb1 or idx == lb2 ):
        return -1

    return idx

