from Crypto.Cipher import AES
from xor_utils import buffer_xor
from typing import Dict,Callable,Tuple


def pkcs7_pad( plaintext:bytes, blocksize:int=16 ) -> bytes:
    data = bytearray(plaintext)
    ptlen = len(plaintext) % blocksize
    pad_byte = blocksize - ptlen
    for i in range(pad_byte):
        data.append(pad_byte)
    return bytes(data)

def pkcs7_unpad( plaintext:bytes, validate:bool=False, blocksize:int=16 ) -> bytes:
    data = bytearray(plaintext)
    data_length = len(data)
    pad_byte = data[data_length-1]

    if validate:
        if pad_byte > blocksize or pad_byte < 0x01:
                raise Exception("Plaintext was incorrectly pkcs7 padded.")

        for i in range(pad_byte):
            if data[(data_length-1)-i] != pad_byte:
                raise Exception("Plaintext was incorrectly pkcs7 padded.")

    data = data[0:data_length-pad_byte]
    return bytes(data)

def split_blocks( input:bytes, blocksize:int=16 ) -> list[bytes]:
    input_length = len(input)
    assert (input_length % blocksize == 0), "Input isnt blocksize aligned, dont forget to pad input."
    blocks = [input[(i)*blocksize:(i+1)*blocksize] for i in range(0, int(input_length/blocksize)) ]
    return blocks

def detect_ecb( ciphertext:bytes, blocksize:int=16 ) -> bool:
    (result,idx) = detect_duplicate_blocks(ciphertext,blocksize)
    return result

def detect_blocksize( oracle_fn:Callable ):
    # find first ciphertext blocksize increase (full padding)
    ctlength = len( oracle_fn( bytes() ) )
    prefix = ''
    ctlength1 = ctlength
    while(  ctlength1 == ctlength ):
        prefix += 'A'
        ctlength1 = len( oracle_fn( bytes(prefix,'utf-8') ) )

    # find second ciphertext blocksize increase
    ctlength2 = ctlength1
    while( ctlength1 == ctlength2 ):
        prefix += 'B'
        ctlength2 = len( oracle_fn( bytes(prefix,'utf-8') ) )

    return ( ctlength2 - ctlength1 )

def detect_blockcipher_metrics( oracle_fn:Callable ) -> Tuple[int,int,int,int,int]:
    ctlength = len( oracle_fn( bytes() ) )
    prefix = ''
    ctlength1 = ctlength
    while(  ctlength1 == ctlength ):
        prefix += 'A'
        ctlength1 = len( oracle_fn( bytes(prefix,'utf-8') ) )
        
    pad_length = len(prefix)
    pt_length = ctlength-pad_length
    blocksize = detect_blocksize(oracle_fn)
    block_count = int(ctlength / blocksize)
    return ( blocksize, block_count, ctlength, pad_length, pt_length )

def detect_duplicate_blocks(ciphertext: bytes, blocksize:int=16 ) -> Tuple[bool,int]:
    dupBlock = ""
    bdict = {}
    blocks = split_blocks(ciphertext)
    for idx,block in enumerate(blocks):
        if block.hex() in bdict:
            dupBlock = block.hex()
            break
        else:
            bdict[block.hex()] = idx
    
    if dupBlock != "":
        return (True, bdict[dupBlock] )
    else:
        return (False,-1)

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)    
    return decrypted

def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(plaintext)
    return encrypted

def encrypt_aes_manual_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"
    assert len(iv) == 16, "IV must be 16 bytes long for AES-128"
    encrypted = bytearray()
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_blocks(plaintext)
    lastblock = iv
    for block in blocks:
        iblock = buffer_xor(block,lastblock)
        lastblock = cipher.encrypt(iblock)
        encrypted.extend(lastblock)

    return bytes(encrypted)

def decrypt_aes_manual_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"
    assert len(iv) == 16, "IV must be 16 bytes long for AES-128"
    decrypted = bytearray()
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = split_blocks(ciphertext)
    lastblock = iv
    for block in blocks:
        iblock = cipher.decrypt(block)
        iblock = buffer_xor(iblock,lastblock)
        decrypted.extend(iblock)
        lastblock = block
        
    return bytes(decrypted)

    