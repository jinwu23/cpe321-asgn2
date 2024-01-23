import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16 # 16 bytes = 128 bits
KEY_LENGTH = 16

def main():
    if len(sys.argv) != 2:
        print("Usage Error: submit.py [plaintext.txt]")
    key = get_random_bytes(KEY_LENGTH)
    iv = get_random_bytes(BLOCK_SIZE)
    print(verify(submit(key, iv), key, iv))
    return

def submit(key, iv):
    input_file = open_file(sys.argv[1], "r")
    user_string = input_file.read()
    user_string = "userid=456;userdata=" + url_encode(user_string) + ";session-id=31337"
    print("Submitted String: " + user_string)
    padded_user_string = pad_string(user_string.encode('utf-8'))
    ciphertext = encrypt(padded_user_string, key, iv)

    xor = ord('#') ^ ord(';')
    xor1 = ciphertext[32] ^ xor

    xor = ord('^') ^ ord('=')
    xor2 = ciphertext[38] ^ xor

    xor = ord('#') ^ ord(';')
    xor3 = ciphertext[43] ^ xor

    ciphertext = bytearray(ciphertext)
    ciphertext[32] = xor1
    ciphertext[38] = xor2
    ciphertext[43] = xor3
    ciphertext = bytes(ciphertext)
    return ciphertext

def verify(string, key, iv):
    plaintext = decrypt(string, key, iv)
    plaintext = unpad_string(plaintext)        
    # plaintext = plaintext.decode('utf-8')
    print("Verified String: " + str(plaintext))
    if ";admin=true;" in str(plaintext):
        return True
    return False

def url_encode(string):
    encoded_string = []
    for character in string:
        if character in "=;":
            encoded_string.append('%{:02X}'.format(ord(character)))
        else:
            encoded_string.append(character)
    return ''.join(encoded_string)      

def open_file(file, mode):
    try:
        input_file = open(file, mode)
    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print(f"An error occured: {e}")    
    return input_file

def pad_string(string):
    padded_string = b''
    for i in range(0, len(string), BLOCK_SIZE):
        block = string[i:i+BLOCK_SIZE]
        if len(block) != BLOCK_SIZE:
            block = pkcs7_pad(block)
        padded_string += block
    return padded_string

def unpad_string(string):
    unpadded_string = b''
    for i in range(0, len(string), BLOCK_SIZE):
        block = string[i:i+BLOCK_SIZE]
        if is_padded(block):
            block = pkcs7_unpad(block)
        unpadded_string += block
    return unpadded_string

def is_padded(block):
    last_byte = block[-1]
    if block.endswith(bytes([last_byte]) * int(last_byte)):
        return True
    return False   

def pkcs7_pad(block):
    bytes_missing = BLOCK_SIZE - len(block)
    return block + bytes([bytes_missing] * bytes_missing)

def pkcs7_unpad(block):
    return block[:-block[-1]]

def encrypt(string, key, iv):
    ciphertext = b'' 
    cipher = AES.new(key, AES.MODE_ECB)
    vector = iv
    for i in range(0, len(string), BLOCK_SIZE):
        block = string[i:i+BLOCK_SIZE]
        vector_as_int = int.from_bytes(vector, byteorder="big")
        block_as_int = int.from_bytes(block, byteorder="big")
        xored_int = vector_as_int ^ block_as_int
        xored_block = xored_int.to_bytes(BLOCK_SIZE, byteorder="big")
        encrypted_block = cipher.encrypt(xored_block)
        ciphertext += encrypted_block
        vector = encrypted_block
    return ciphertext

def decrypt(ciphertext, key, iv):
    plaintext = b""
    cipher = AES.new(key, AES.MODE_ECB)
    vector = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        cipher_block = bytes(ciphertext[i:i+BLOCK_SIZE])
        decrypted_block = cipher.decrypt(cipher_block)
        vector_as_int = int.from_bytes(vector, byteorder="big")
        block_as_int = int.from_bytes(decrypted_block, byteorder="big")
        xored_int = vector_as_int ^ block_as_int
        xored_block = xored_int.to_bytes(BLOCK_SIZE, byteorder="big")
        plaintext += xored_block
        vector = cipher_block
    return plaintext

if __name__ == "__main__":
    main()