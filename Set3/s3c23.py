# Matasano Crypto Challenges
# Set 3, Challenge 23 - Clone an MT19937 from its output
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
import mt19937 as mt
import random



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


