import sys
sys.path.append('../utils')
from block_utils import encrypt_aes_ecb
from xor_utils import buffer_xor
from mt19937 import MT19937Generator

def AesCtrKeystreamGenerator( key, nonce:bytes ):
    assert len(nonce)==8, "Nonce must be 64 bit value."
    ctr_counter = 0
    keybytes = bytes(16)
    key_idx = 16
    pt = bytearray()

    while True:
        key_idx = key_idx+1
        
        if(key_idx > 15):
            pt = bytearray()
            pt.extend(nonce)
            pt.extend(ctr_counter.to_bytes(8,"little"))
            keybytes = encrypt_aes_ecb( pt, key )
            ctr_counter += 1
            key_idx = 0       
        
        yield keybytes[key_idx]

def encrypt_aes_ctr( plaintext:bytes, key:bytes, nonce:bytes ) -> bytes:       
    ctr = AesCtrKeystreamGenerator( key, nonce )
    ciphertext = buffer_xor( plaintext, ctr )
    return ciphertext

def decrypt_aes_ctr( ciphertext:bytes, key:bytes, nonce:bytes ) -> bytes:
    return encrypt_aes_ctr( ciphertext, key, nonce )

def encrypt_mt19937_stream( plaintext:bytes, seed:int ) -> bytes:       
    mtgen = MT19937Generator( seed )
    ciphertext = buffer_xor( plaintext, mtgen )
    return ciphertext

def decrypt_mt19937_stream( ciphertext:bytes, seed:int ) -> bytes:
    return encrypt_mt19937_stream( ciphertext, seed )
