# Matasano Crypto Challenges
# Set 4, Challenge 29 - Implement a SHA-1 keyed MAC
#
import time
import requests

url_hmac = "http://127.0.0.1:5000/hmac"
url_validate =  "http://127.0.0.1:5000/validate"
expected_api_version = 1


def get_time():
    tick_count = time.time()
    return tick_count

def avg_validation_time( current_guess, i, data, api_request_fn ):
    avg_validation_time = 0
    for n in range(10):
        current_guess[i] = n
        start_time = get_time()
        api_request_fn( data, current_guess.hex() )
        end_time = get_time()
        avg_validation_time += ( end_time - start_time )
    
    avg_validation_time = avg_validation_time / 10
    return avg_validation_time

def validate_next_byte( current_byte_avg, next_byte_exp, timings ):
    # Sort and validate timings
    timings.sort( key=lambda tpl: tpl[1], reverse=True )
    for timing in timings:
        if( (next_byte_exp - timing[1]) < ( timing[1] - current_byte_avg )):
            return timing[0]  

def hmac_timing_attack( data, api_request_fn, count=3, resume=False ):

    if(resume):
        hmac_guess = bytearray(resume)
    else: 
        hmac_guess = bytearray([0x00] * 20)

    # Brute force the hmac, looking for timing changes.
    last_byte_avg = 0

    for i in range(20):

        # Get metrics for the current byte
        current_byte_avg = avg_validation_time( hmac_guess, i, data, api_request_fn )
        next_byte_exp = current_byte_avg + (current_byte_avg - last_byte_avg)
        
        print(f'Last Byte Avg:\t\t{last_byte_avg}')
        print(f'Current Byte Avg:\t{current_byte_avg}')
        print(f'Next Byte Exp:\t\t{next_byte_exp}')

        # Collect data for hmac_guess[i].
        hmac_timings = list()
        for j in range(256):
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
       
        # Analyze / Process Data for byte
        hmac_guess[i] = validate_next_byte( current_byte_avg, next_byte_exp, hmac_timings )
        print( f"\t\t{hmac_guess.hex()}" )
        last_byte_avg = current_byte_avg

    return ( False, hmac_guess )
               

def request_hmac(data):
    payload = {"data": data }
    response = requests.get( url_hmac, params=payload )
    jdict = response.json()

    api_version = jdict['apiVersion']
    if( api_version is None):
        exit('Target API did not return an api version.')
    elif( api_version != expected_api_version ):
        exit('Target API did not return the expected api version.  Expected: {expected_api_version}, Received: {api_version}')

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

print('Matasano Crypto Challenges')
print('Set 4, Challenge 31 - Break a HMAC-SHA1 with artificial timing leak')
print('-------------------------------------------------------------------')

data = b"abcdef"
secret_hmac = request_hmac(data)
print(f'secret hmac:\t{secret_hmac}' )

(result, hmac ) = hmac_timing_attack( data, request_validate )

if( result ):
    print(f'Identified hmac for file as: {hmac.hex()}')
else:
    print("Attack Failed")
