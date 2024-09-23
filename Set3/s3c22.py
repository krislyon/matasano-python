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

def getRNGOutput( count, wait_time_max ):
    seed = int(time.time())
    waittime =  random.randint(20, wait_time_max )
    print('Waiting for: ' + str(waittime))
    time.sleep( waittime )
    rng = mt.MT19937(seed)
    return ([rng.rand32() for i in range(count)], seed )

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

def run_challenge_22( wait_time_max=1000):
    print('Matasano Crypto Challenges')
    print('Set 3, Challenge 22 - Crack an MT19937 seed')
    print('-------------------------------------------')


    (output,secret_seed) = getRNGOutput( 100, wait_time_max )
    rseed = recoverTimeSeed( output )

    rng = mt.MT19937(rseed)
    recovered = [rng.rand32() for i in range(5)]

    for i in range(5):
        print('Stream:' + str(output[i]) + ', Recovered: ' + str(recovered[i]) )

    return rseed, secret_seed

if __name__ == '__main__':
    run_challenge_22()