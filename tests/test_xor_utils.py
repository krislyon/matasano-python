import sys
import unittest
import itertools
import random
sys.path.append('../utils')

from xor_utils import *

class Test_RepeatingKeyGenerator( unittest.TestCase ):

    def test_generator_stream(self):
        stream = itertools.islice( RepeatingKeyGenerator('A'), 1000 )
        for b in stream:
            self.assertEqual( b, 'A', 'Keystream contained unknown data.')
    
    def test_generator_stream_word(self):
        keyword = 'ABCDE'
        stream = itertools.islice( RepeatingKeyGenerator( keyword ), 1000 )
        for idx,b in enumerate(stream):
            self.assertEqual( b, keyword[idx%len(keyword)], 'Keystream contained unknown data.')

class Test_BufferGenerator( unittest.TestCase ):

    def test_generator_stream(self):
        streamdata = random.randbytes(1000)
        buf_generator = BufferGenerator( streamdata )
        stream = itertools.islice( buf_generator, 1000 )

        for idx,b in enumerate(stream):
            self.assertEqual( b, streamdata[idx], 'Keystream contained unknown data.')

class Test_create_xor_key( unittest.TestCase ):

    def test_creation(self):
        key = create_xor_key( ord('A'), 100 )
        self.assertEqual( len(key), 100 )
        self.assertEqual( key, bytes('A' * 100,'utf-8') )

class Test_create_repeating_key_buffer( unittest.TestCase ):

    def test_buffer_creation(self):
        keyword = 'ABCDE'
        stream = create_repeating_key_buffer( keyword, 1000 )
        for idx,b in enumerate(stream):
            self.assertEqual( b, ord(keyword[idx%len(keyword)]), 'Keystream contained unknown data.')        

class Test_buffer_xor( unittest.TestCase ):

    def test_xor(self):
        expected = "30333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534303332353430333235343033323534"
        buf1 = create_repeating_key_buffer('ABCDE',100)
        buf2 = create_xor_key( 113, 100 )
        result = buffer_xor( buf1, buf2 )
        self.assertEqual( result.hex(), expected, 'Buffer XOR didnt match expected result.' )

class Test_repeating_key_xor( unittest.TestCase ):

    def test_repeating_xor(self):
        expected = "0a23366326263626623b2e2c2f73362f2c6c20633c3c3a2a2124342020733626372f2a7c"
        data = bytes("How much wood can a woodchuck chuck?",'utf-8')
        result = repeating_key_xor( data, 'BLACKSUN' )
        self.assertEqual( result.hex(), expected, 'Buffer XOR didnt match expected result.' )

class Test_transpose_data_blocks(unittest.TestCase):

    def test_empty_blocks(self):
        result = transpose_data_blocks( bytes(), 5 )
        self.assertEqual( result, [ bytes(), bytes(), bytes(), bytes(), bytes() ] )

    def test_even_blocks(self):
        data = bytes("ABCDEABCDEABCDEABCDEABCDEABCDE",'utf-8')
        result = transpose_data_blocks( data, 5 )
        self.assertEqual( result, [ bytes("AAAAAA",'utf-8'), bytes("BBBBBB",'utf-8'), bytes("CCCCCC",'utf-8'), bytes("DDDDDD",'utf-8'), bytes("EEEEEE",'utf-8') ] )

    def test_uneven_blocks(self):
        data = bytes("ABCDEABCDEABCDEABCDEABCDEABC",'utf-8')
        result = transpose_data_blocks( data, 5 )
        self.assertEqual( result, [ bytes("AAAAAA",'utf-8'), bytes("BBBBBB",'utf-8'), bytes("CCCCCC",'utf-8'), bytes("DDDDD",'utf-8'), bytes("EEEEE",'utf-8') ] )

class Test_detect_diff_start( unittest.TestCase ):

    def test_diff_at_start(self):
        buf1 = bytes("ABCDEFG",'utf-8')
        buf2 = bytes("XBCDEFG",'utf-8')
        idx = detect_diff_start( buf1, buf2 )
        self.assertEqual( idx, 0 )

    def test_diff_at_mid(self):
        buf1 = bytes("ABCXEFG",'utf-8')
        buf2 = bytes("ABCDEFG",'utf-8')
        idx = detect_diff_start( buf1, buf2 )
        self.assertEqual( idx, 3 )

    def test_diff_at_end(self):
        buf1 = bytes("ABCDEFX",'utf-8')
        buf2 = bytes("ABCDEFG",'utf-8')
        idx = detect_diff_start( buf1, buf2 )
        self.assertEqual( idx, 6 )

    def test_no_diff(self):
        buf1 = bytes("ABCDEFG",'utf-8')
        buf2 = bytes("ABCDEFG",'utf-8')
        idx = detect_diff_start( buf1, buf2 )
        self.assertEqual( idx, -1 )
    
class Test_detect_diff_end( unittest.TestCase ):

    def test_no_diff_at_start(self):
        buf1 = bytes("ABCDEFG",'utf-8')
        buf2 = bytes("ABCDEFG",'utf-8')
        idx = detect_diff_end( buf1, buf2 )
        self.assertEqual( idx, 0 )

    def test_no_diff_at_mid(self):
        buf1 = bytes("XXXDEFG",'utf-8')
        buf2 = bytes("YYYDEFG",'utf-8')
        idx = detect_diff_end( buf1, buf2 )
        self.assertEqual( idx, 3 )

    def test_no_diff_at_end(self):
        buf1 = bytes("XXXXXXA",'utf-8')
        buf2 = bytes("YYYYYYA",'utf-8')
        idx = detect_diff_end( buf1, buf2 )
        self.assertEqual( idx, 6 )

    def test_all_diff(self):
        buf1 = bytes("XXXXXXX",'utf-8')
        buf2 = bytes("YYYYYYY",'utf-8')
        idx = detect_diff_end( buf1, buf2 )
        self.assertEqual( idx, -1 )
    
class Test_calculate_xor_keysize( unittest.TestCase ):

    def test_recover_keysize(self):
        test_data = "I wanna heal, I wanna feel what I thought was never real\nI wanna let go of the pain I've felt so long"
        for keylen in range(1,5):
            key = random.randbytes(keylen)
            ct = buffer_xor( bytes(test_data,'utf-8'), RepeatingKeyGenerator(key) )
            (ks,ksdict) = calculate_xor_keysize( ct, 15, debug=True )

            print(ksdict)


            if( ksdict.get( keylen ) == None ):
                keylist = [k for k in ksdict.keys() if ksdict[k] > 2.0]
                self.assertTrue( keylen in keylist, "Keysize was not in candidate list with a score above threshold value: " + str(2.0) )



unittest.main()
