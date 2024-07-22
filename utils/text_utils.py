oxford_character_distribution = {
    'a': 0.084966,
    'b': 0.020720,
    'c': 0.045388,
    'd': 0.036308,
    'e': 0.111607,
    'f': 0.018121,
    'g': 0.024705,
    'h': 0.030034,
    'i': 0.075488,
    'j': 0.001965,
    'k': 0.011016,
    'l': 0.054893,
    'm': 0.030129,
    'n': 0.066544,
    'o': 0.071635,
    'p': 0.031671,
    'q': 0.001962,
    'r': 0.075809,
    's': 0.057351,
    't': 0.069509,
    'u': 0.036308,
    'v': 0.010074,
    'w': 0.012899,
    'x': 0.002902,
    'y': 0.017779,
    'z': 0.002722    
}

def frequency_score(buffer:bytes) -> list[float]:
    if len(buffer) == 0:
        return 0

    freqArray = [256]
    
    for i in range(256):
        freqArray[i] = 0

    for i in range( len(buffer) ):
        c = buffer[i]
        freqArray[c] = freqArray[c] = freqArray[c] + 1
    
    for i in range(256):
        freqArray[i] = freqArray[i] / len(buffer)

    return freqArray

def in_ascii_alpha_range(c:int) -> bool:
    if ( ((c>=48) and (c<=57)) or ((c>=65) and (c<=90)) or ((c>=97) and (c<=122)) or (c==32) ):
        return True
    else:
        return False

def ascii_range_score( buf: bytes ) -> float:
    if len(buf) == 0:
        return 0
    score = 0
    for byte in buf:
        if in_ascii_alpha_range( byte ):
            score = score + 1
    return score / len(buf)

def bitwise_hamming_distance( string_a:str, string_b:str ) -> float:
    if len(string_a) != len(string_b):
        raise ValueError("Strings must be of the same length")
    
    # Calculate the bitwise hamming distance
    distance = 0
    for c1, c2 in zip(string_a, string_b):
        # XOR the characters and count the number of 1s in the result
        distance += bin(c1 ^ c2).count('1')

    return distance / len(string_a)

def hexdump(src: bytes, bytesPerLine: int = 16, bytesPerGroup: int = 4, sep: str = '.') -> list[str]:
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    maxAddrLen = len(hex(len(src)))
    if 8 > maxAddrLen:
        maxAddrLen = 8

    for addr in range(0, len(src), bytesPerLine):
        hexString = ""
        printable = ""

        # The chars we need to process for this line
        chars = src[addr : addr + bytesPerLine]

        # Create hex string
        tmp = ''.join(['{:02X}'.format(x) for x in chars])
        idx = 0
        for c in tmp:
            hexString += c
            idx += 1
            # 2 hex digits per byte.
            if idx % bytesPerGroup * 2 == 0 and idx < bytesPerLine * 2:
                hexString += " "
        # Pad out the line to fill up the line to take up the right amount of space to line up with a full line.
        hexString = hexString.ljust(bytesPerLine * 2 + int(bytesPerLine * 2 / bytesPerGroup) - 1)

        # create printable string
        tmp = ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        # insert space every bytesPerGroup
        idx = 0
        for c in tmp:
            printable += c
            idx += 1
            # Need to check idx because strip() would also delete genuine spaces that are in the data.
            if idx % bytesPerGroup == 0 and idx < len(chars):
                printable += " "

        lines.append(f'{addr:0{maxAddrLen}X}  {hexString}  |{printable}|')
    return lines

def print_data( name: str, data: bytes, count:int=-1, cols:int=80 ):
    if( count == -1 ):
        count = len(data)

    print( name + ':')
    print( '-' * cols )  
    print( *hexdump( data, 32, 8, '.'), sep="\n")

def hex_space( data:bytes ):
    hex_string = data.hex()
    return ' '.join(hex_string[i:i+8] for i in range(0, len(hex_string), 8))
