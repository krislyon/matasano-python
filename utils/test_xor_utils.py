import unittest
from xor_utils import *

class Test_create_xor_key( unittest.TestCase ):

    def test_xxx(self):
        keylength = 5
        value = 25
        key = create_xor_key( keylength, value )
        self.assertEqual( keylength, len(key), 'Resulting key length was unexpected.')
        self.assertEqual( key, bytes([value] * keylength), 'key was different than expected' )

if __name__ == '__main__':
    unittest.main()
