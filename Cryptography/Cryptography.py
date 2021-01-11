import hashlib
import hmac
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def pad(text,num):
    while len(text) % num != 0:
        text += ' '
    return text


def makekey(key):
    hash_value = hashlib.sha256(key.encode())
    key = hash_value.digest()
    return key


def cipher_func(cipher_type):
    if cipher_type == "DES":
        key = input("key: ")
        key = makekey(key)
        key = key[:8]
        des = DES.new(key, DES.MODE_ECB)
        padded_text = pad(original_data,8)
        encrypted_text = des.encrypt(padded_text.encode())
        print("encrypted: ", end='')
        print(encrypted_text)
        decrypted_text = des.decrypt(encrypted_text)
        print("decrypted: "+decrypted_text.decode())

    elif cipher_type == "DES3":
        key = input("key: ")
        key = makekey(key)
        key = key[:24]
        IV = "0123456789"
        IV = makekey(IV)
        IV = IV[:8]
        des3 = DES3.new(key, DES3.MODE_CBC,IV)
        padded_text = pad(original_data,8)
        encrypted_text = des3.encrypt(padded_text.encode())
        print("encrypted: ", end='')
        print(encrypted_text)
        des3 = DES3.new(key, DES3.MODE_CBC, IV)
        decrypted_text = des3.decrypt(encrypted_text)
        print("decrypted: " + decrypted_text.decode())

    elif cipher_type == "AES":
        key = input("key(16/24/32): ")
        keylen = len(key)
        key = makekey(key)
        if keylen ==16 or keylen==24 or keylen==32:
            key=key[:keylen]
        else:
            key = key[:16]

        IV = "1234"
        IV = makekey(IV)
        IV = IV[:16]

        aes = AES.new(key, AES.MODE_CBC,IV)
        padded_text = pad(original_data, 16)
        encrypted_text = aes.encrypt(padded_text.encode())
        print("encrypted: ", end='')
        print(encrypted_text)

        aes = AES.new(key, AES.MODE_CBC, IV)
        decrypted_text = aes.decrypt(encrypted_text)
        print("decrypted: " + decrypted_text.decode())

    elif cipher_type == "ARC4":
        key = input("key(more than 5 letter, less than 256 letter): ")
        key= key.encode()
        arc4=ARC4.new(key)
        encrypted_text = arc4.encrypt(original_data.encode())
        print("encrypted: ", end='')
        print(encrypted_text)
        arc4 = ARC4.new(key)
        decrypted_text = arc4.decrypt(encrypted_text)
        print("decrypted: " + decrypted_text.decode())


def hash_value(hash_type):
    if hash_type == "SHA":
        hash_result = hashlib.sha1(original_data.encode())
        print(hash_result.hexdigest())
    elif hash_type == "SHA256":
        hash_result = hashlib.sha256(original_data.encode())
        print(hash_result.hexdigest())
    elif hash_type == "SHA384":
        hash_result = hashlib.sha384(original_data.encode())
        print(hash_result.hexdigest())
    elif hash_type == "SHA512":
        hash_result = hashlib.sha512(original_data.encode())
        print(hash_result.hexdigest())
    elif hash_type == "HMAC":
        hash_result = hmac.new(original_data.encode())
        print(hash_result.hexdigest())


def RSA_func():
    number = input("key length(x256, >=1024): ")
    private_key = RSA.generate(int(number))
    public_key = private_key.publickey()
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(original_data.encode())
    print("encrypted:", end='')
    print(encrypted)
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(encrypted)
    print("decrypted: ", end='')
    print(decrypted.decode())


if __name__ == "__main__":
    original_data = input("original data: ")
    cipher_type = input("cipher type(DES/DES3/AES/ARC4): ")
    cipher_func(cipher_type)
    print("\n")
    hash_type = input("hash type(SHA/SHA256/SHA384/SHA512/HMAC): ")
    hash_value(hash_type)
    print("\n")
    print("RSA")
    RSA_func()