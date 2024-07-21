# Matasano Crypto Challenges
# Set 3, Challenge 21 - Implement the MT19937 Mersenne Twister RNG
#
import sys
sys.path.append('../utils')
import mt19937 as mt

def load_test_data( filename: str ) -> bytes:
    with open( filename, 'r') as file:
        return [ int(line) for line in file.readlines()]
        
if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 3, Challenge 21 - Implement the MT19937 Mersenne Twister RNG')
    print('----------------------------------------------------------------')

    expected_outputs = load_test_data('s3c21.dat')
    rng = mt.MT19937(1131464071)
    for i, expected in enumerate(expected_outputs):
        generated = rng.rand32()
        assert generated == expected, f"Output {i+1}: Expected {expected}, got {generated}"

    print("Test vector validated successfully.")