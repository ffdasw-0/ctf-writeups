import base58
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

if __name__ == '__main__':

    key=[0x1CCD4928604D14F8,0x7143CE7C15426266]
    aes_key=key[0].to_bytes(8,"little")+key[1].to_bytes(8,"little")
    print(aes_key)
    cipher_text="8CRFoGsg8eBPnbE53XMNNmCvBbQEaKZuFkVhoTweoVQLozxhHaXKm2oSvcsGxxPCuR"
    cipher_text1=base58.b58decode(cipher_text)
    plain_text=aes_decrypt(aes_key, cipher_text1).decode('utf-8', errors='ignore')
    print(plain_text)