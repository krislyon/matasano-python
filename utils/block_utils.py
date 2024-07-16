from Crypto.Cipher import AES
from xor_utils import buffer_xor

def pkcs7_pad( plaintext:bytes, blocksize:int=16 ) -> bytes:
    data = bytearray(plaintext)
    ptlen = len(plaintext) % blocksize
    pad_byte = blocksize - ptlen
    for i in range(pad_byte):
        data.append(pad_byte)
    return bytes(data)

def pkcs7_unpad( plaintext:bytes, blocksize:int=16 ) -> bytes:
    data = bytearray(plaintext)
    data_length = len(data)
    pad_byte = data[data_length-1]
    data = data[0:data_length-pad_byte]
    return bytes(data)


def split_blocks( input:bytes, blocksize:int=16 ) -> list[bytes]:
    input_length = len(input)
    assert (input_length % blocksize == 0), "Input isnt blocksize aligned, dont forget to pad input."
    blocks = [input[(i)*blocksize:(i+1)*16] for i in range(0, int(input_length/blocksize)) ]
    return blocks


def detect_ecb( ciphertext:bytes, blocksize:int=16 ) -> bool:
    bdict = {}
    blocks = split_blocks(ciphertext)
    for block in blocks:
        if block.hex() in bdict:
            return True
        else:
            bdict[block.hex()] = 1
    return False


def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)    
    return decrypted

def encrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(ciphertext)
    return encrypted

def encrypt_aes__manual_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
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
