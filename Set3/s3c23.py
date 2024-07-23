# Matasano Crypto Challenges
# Set 3, Challenge 23 - Clone an MT19937 from its output
#
import sys
sys.path.append('../utils')
import mt19937 as mt
import random
import time


if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 3, Challenge 23 - Clone an MT19937 from its output')
    print('------------------------------------------------------')

randseed = random.randint(0,0xffffffff)
rng = mt.MT19937(randseed)
rng_output = [ rng.rand32() for i in range(624) ] 

recovered_rng_state = [ mt.untemper(x) for x in rng_output ]
cloned_rng = mt.MT19937()
cloned_rng.loadstate( 624, recovered_rng_state )

print("Next 5 Numbers from Original RNG:")
print([ rng.rand32() for i in range(5)])

print("Next 5 Numbers from Cloned RNG:")
print([ cloned_rng.rand32() for i in range(5)])


