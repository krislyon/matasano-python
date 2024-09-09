# Matasano Crypto Challenges
# Set 4, Challenge 29 - Implement a SHA-1 keyed MAC
#
import sys
import time
import requests
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from statistics import median

url_hmac = "http://127.0.0.1:5000/hmac"
url_validate =  "http://127.0.0.1:5000/validate"
expected_api_version = 2

def get_time():
    tick_count = time.time()
    return tick_count

def format_time(seconds):
    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60   
    formatted_time = f"{minutes}m {remaining_seconds:.0f}s"
    return formatted_time

def request_hmac(data):
    payload = {"data": data }
    response = requests.get( url_hmac, params=payload )
    jdict = response.json()

    api_version = jdict['apiVersion']
    if( api_version is None):
        exit('Target API did not return an api version.')
    elif( api_version != expected_api_version ):
        exit(f'Target API did not return the expected api version.  Expected: {expected_api_version}, Received: {api_version}')

    return jdict['signature']

def request_validate(data,sig):
    payload = {"data" : data, "signature" : sig }
    response = requests.get( url_validate, params=payload )
    jdict = response.json()

    api_version = jdict['apiVersion']
    if( api_version is None):
        exit('Target API did not return an api version.')
    elif( api_version != expected_api_version ):
        exit(f'Target API did not return the expected api version.  Expected: {expected_api_version}, Received: {api_version}')

    return jdict['result']

def median_validation_time( sample_count, current_guess, i, data, api_request_fn ):
    validation_times = []
    print(f'Timing Current Byte ({sample_count}):\t', flush=True, end='' )

    for n in range(sample_count):
        if( n%5 == 0 ):
            print('t',end='',flush=True)

        # iterate our guesses so if we accidentally guess right, it' (1/sample_count)
        current_guess[i] = n%255

        start_time = get_time()
        api_request_fn( data, current_guess.hex() )
        end_time = get_time()

        validation_times.append( (end_time-start_time) )

    # trim outliers & return median (this should handle it if we guess right)
    max_time = max(validation_times)
    min_time = min(validation_times)
    validation_times = [ x for x in validation_times if x != max_time and x != min_time ]
    print('\n')
    return median( validation_times )      

def get_next_byte_guess_generator( current_byte_avg, next_byte_exp, timings ):

    def GuessGenerator( guess_list:list ):
        i=0
        while i < len( guess_list ):
            yield guess_list[i]
            i+=1
        raise ValueError('GuessGenerator exceeded list length: ' + str(len(guess_list)))

    # Sort and validate timings
    timings.sort( key=lambda tpl: tpl[1], reverse=True )
    return GuessGenerator( timings )

def validate_guess( hmac_guess, i, expected_timing, last_timing, data, api_request_fn, count=100 ):
    print(f"\nValidating ({hex(hmac_guess[i])}, {count}): ",end='',flush=True)

    timings = []

    for i in range(count):
        if( i%2 == 0 ):
            print('v', end='',flush=True)

        start_time = get_time()
        api_request_fn(data, hmac_guess.hex())
        end_time = get_time()

        timings.append( ( end_time - start_time ) )
        
    max_time = max(timings)
    min_time = min(timings)

    timings = [ x for x in timings if x != max_time and x != min_time ]  
    med = median(timings)
    exp_dist = abs( expected_timing - med )
    last_dist = abs( last_timing - med )

    print(f"\n( med:{med}, last:{last_timing}, exp:{expected_timing}, last-dist:{last_dist}, exp-dist:{exp_dist} )", flush=True)

    if( exp_dist < last_dist ):
        return True
    else:
        return False

def get_hmac_timings_for_byte( hmac_guess, i, data, api_request_fn, count=3 ):
        # Collect data for hmac_guess[i].
        hmac_timings = list()

        print(f'Attacking Byte ({count}): ', flush=True, end='')

        for j in range(256):

            if( j%10 == 0):
                print('.',end='',flush=True)

            hmac_guess[i] = j
            tdata = list()
            hmac_hex = hmac_guess.hex()
            
            for k in range(count):
                start_time = get_time()
                result = api_request_fn( data, hmac_hex )
                end_time = get_time()
                tdata.append((end_time - start_time))
                
                if( result == 200 ):
                    return ( True, hmac_guess )

            hmac_timings.append( (j,sum(tdata)/len(tdata)) )
        return hmac_timings

def hmac_timing_attack( hmac_secret, data, api_request_fn ):

    validation_sample_count = 50
    samples_per_byte = 50

    hmac_guess = bytearray([0x00] * 20)
    last_byte_avg = 0
    for i in range(20):
        print()
        print(f'Processing Byte ({i+1}/20):')
        print('------------------------------------------------------------------------')
        print( f"Actual (secret):\t\t{hmac_secret}")
        print( f"Current Guess: \t\t\t{hmac_guess.hex()}" )
        # Get metrics for the current byte
        current_byte_avg = median_validation_time( validation_sample_count, hmac_guess, i, data, api_request_fn )
        next_byte_exp = current_byte_avg + (current_byte_avg - last_byte_avg)
        
        print(f'Last Byte Avg:\t\t\t{last_byte_avg}')
        print(f'Current Byte Avg:\t\t{current_byte_avg}')
        print(f'Next Byte Exp:\t\t\t{next_byte_exp}')
        print()
        print(f'Estimated Byte Completion in: {format_time(current_byte_avg * samples_per_byte * 255)}.')
        print()

        byte_start_time = get_time()
        
        current_byte_timings = get_hmac_timings_for_byte( hmac_guess, i, data, api_request_fn, samples_per_byte )

        if( current_byte_timings[0] ):
            print('Success, aborting search.')            
            return ( True, current_byte_timings[1] )

        # Analyze / Process Data for byte
        byteGuessGenerator = get_next_byte_guess_generator( current_byte_avg, next_byte_exp, current_byte_timings )       
        hmac_guess[i] = next(byteGuessGenerator)[0]
        while( not validate_guess(hmac_guess, i, next_byte_exp, current_byte_avg, data, api_request_fn ) ):
            print('X',end='',flush=True)
            hmac_guess[i] = next(byteGuessGenerator)[0]

        
        print()
        print(f'Completed Byte in {format_time(get_time() - byte_start_time)} seconds.')
        last_byte_avg = current_byte_avg

    return ( False, hmac_guess )
               

print('Matasano Crypto Challenges')
print('Set 4, Challenge 32 - Break a HMAC-SHA1 with less artificial timing leak')
print('------------------------------------------------------------------------')

# enhance wrong byte selection detection
# add resume
# add command line options / tuning
# add a time estimate for each stage

data = b"abcdef"
secret_hmac = request_hmac(data)
print(f'secret hmac:\t{secret_hmac}' )

(result, hmac ) = hmac_timing_attack( secret_hmac, data, request_validate )

if( result ):
    print(f'Identified hmac for file as: {hmac.hex()}')
else:
    print("Attack Failed")
