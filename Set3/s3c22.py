# Matasano Crypto Challenges
# Set 3, Challenge 22 - Crack an MT19937 seed
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
import mt19937 as mt
import random
import time

def getRNGOutput( count ):
    seed = int(time.time())
    waittime =  random.randint(20,1000)
    print('Waiting for: ' + str(waittime))
    time.sleep( waittime )
    rng = mt.MT19937(seed)
    return [rng.rand32() for i in range(count)]

def recoverTimeSeed( known_output ):
    print('Beginning Recovery.')
    startTime = int(time.time())
    minTime = startTime - 3000
    maxTime = startTime + 500

    for seed in range( minTime, maxTime ):
        rng = mt.MT19937(seed)
        rngList = [rng.rand32() for i in range(100)]

        if( known_output[0] in rngList ):
            print('Seed Recovered: ' + str(seed) )
            endTime = int(time.time())
            print('Recovery Completed in: ' + str(endTime- startTime) )
            return seed


print('Matasano Crypto Challenges')
print('Set 3, Challenge 22 - Crack an MT19937 seed')
print('-------------------------------------------')


output = getRNGOutput( 100 )
rseed = recoverTimeSeed( output )

rng = mt.MT19937(rseed)
recovered = [rng.rand32() for i in range(5)]

for i in range(5):
    print('Stream:' + str(output[i]) + ', Recovered: ' + str(recovered[i]) )

