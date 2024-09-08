import sys
import os
import itertools
import random
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from xor_utils import *

def test___RepeatingKeyGenerator___stream_char():
    stream = itertools.islice( RepeatingKeyGenerator('A'), 1000 )
    for b in stream:
        assert b == 'A', 'Keystream contained unknown data.'

def test___RepeatingKeyGenerator___stream_word():
    keyword = 'ABCDE'
    stream = itertools.islice( RepeatingKeyGenerator( keyword ), 1000 )
    for idx,b in enumerate(stream):
        assert b == keyword[idx%len(keyword)], 'Keystream contained unknown data.'


def test___BufferGenerator___stream_buf():
    streamdata = random.randbytes(1000)
    buf_generator = BufferGenerator( streamdata )
    stream = itertools.islice( buf_generator, 1000 )

    for idx,b in enumerate(stream):
        assert b == streamdata[idx], 'Keystream contained unknown data.'


def test___create_xor_key():
    key = create_xor_key( ord('A'), 100 )
    assert len(key) == 100 
    assert key == bytes('A' * 100,'utf-8') 


def test___create_repeating_key_buffer():
    keyword = 'ABCDE'
    stream = create_repeating_key_buffer( keyword, 1000 )
    for idx,b in enumerate(stream):
        assert b == ord(keyword[idx%len(keyword)]), 'Keystream contained unknown data.'    


def test___buffer_xor():
    expected = "30333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534"
    buf1 = create_repeating_key_buffer('ABCDE',100)
    buf2 = create_xor_key( 113, 100 )
    result = buffer_xor( buf1, buf2 )
    assert result.hex() == expected, 'Buffer XOR didnt match expected result.'


def test___repeating_key_xor():
    expected = "0a23366326263626623b2e2c2f73362f2c6c20633c3c3a2a2124342020733626372f2a7c"
    data = bytes("How much wood can a woodchuck chuck?",'utf-8')
    result = repeating_key_xor( data, 'BLACKSUN' )
    assert result.hex() == expected, 'Buffer XOR didnt match expected result.' 

def test___transpose_data_blocks___empty():
    result = transpose_data_blocks( bytes(), 5 )
    assert result == [ bytes(), bytes(), bytes(), bytes(), bytes() ]

def test___transpose_data_blocks___even_count():
    data = bytes("ABCDEABCDEABCDEABCDEABCDEABCDE",'utf-8')
    result = transpose_data_blocks( data, 5 )
    assert result == [ bytes("AAAAAA",'utf-8'), bytes("BBBBBB",'utf-8'), bytes("CCCCCC",'utf-8'), bytes("DDDDDD",'utf-8'), bytes("EEEEEE",'utf-8') ] 

def test___transpose_data_blocks___uneven_count():
    data = bytes("ABCDEABCDEABCDEABCDEABCDEABC",'utf-8')
    result = transpose_data_blocks( data, 5 )
    assert result == [ bytes("AAAAAA",'utf-8'), bytes("BBBBBB",'utf-8'), bytes("CCCCCC",'utf-8'), bytes("DDDDD",'utf-8'), bytes("EEEEE",'utf-8') ] 

def test___detect_diff_start___start():
    buf1 = bytes("ABCDEFG",'utf-8')
    buf2 = bytes("XBCDEFG",'utf-8')
    idx = detect_diff_start( buf1, buf2 )
    assert idx == 0 

def test___detect_diff_start___mid():
    buf1 = bytes("ABCXEFG",'utf-8')
    buf2 = bytes("ABCDEFG",'utf-8')
    idx = detect_diff_start( buf1, buf2 )
    assert idx == 3 

def test___detect_diff_start___end():
    buf1 = bytes("ABCDEFX",'utf-8')
    buf2 = bytes("ABCDEFG",'utf-8')
    idx = detect_diff_start( buf1, buf2 )
    assert idx == 6

def test___detect_diff_start___no_diff():
    buf1 = bytes("ABCDEFG",'utf-8')
    buf2 = bytes("ABCDEFG",'utf-8')
    idx = detect_diff_start( buf1, buf2 )
    assert idx == -1
    
def test___detect_diff_end___no_diff():
    buf1 = bytes("ABCDEFG",'utf-8')
    buf2 = bytes("ABCDEFG",'utf-8')
    idx = detect_diff_end( buf1, buf2 )
    assert idx == 0

def test___detect_diff_end___diff_at_mid():
    buf1 = bytes("XXXDEFG",'utf-8')
    buf2 = bytes("YYYDEFG",'utf-8')
    idx = detect_diff_end( buf1, buf2 )
    assert idx == 3

def test___detect_diff_end___diff_at_end():
    buf1 = bytes("XXXXXXA",'utf-8')
    buf2 = bytes("YYYYYYA",'utf-8')
    idx = detect_diff_end( buf1, buf2 )
    assert idx == 6

def test___detect_diff_end___all_diff():
    buf1 = bytes("XXXXXXX",'utf-8')
    buf2 = bytes("YYYYYYY",'utf-8')
    idx = detect_diff_end( buf1, buf2 )
    assert idx == -1 

def test___recover_keysize():
    test_data = "I wanna heal, I wanna feel what I thought was never real\nI wanna let go of the pain I've felt so long"
    for keylen in range(1,5):
        key = random.randbytes(keylen)
        ct = buffer_xor( bytes(test_data,'utf-8'), RepeatingKeyGenerator(key) )
        (ks,ksdict) = calculate_xor_keysize( ct, 15, debug=True )

        print(ksdict)


        if( ksdict.get( keylen ) == None ):
            keylist = [k for k in ksdict.keys() if ksdict[k] > 2.0]
            assert keylen in keylist, "Keysize was not in candidate list with a score above threshold value: " + str(2.0) 
