import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

block_size = 16 # 16 bytes (128 bits) 
bmp_header_size = 54 # 54 bytes
key_length = 16 # 16 byte key

def main():
    if len(sys.argv) != 3 or not(sys.argv[1] != "ecb" or sys.argv[1] != "cbc"):
        print("Usage Error: encrypt.py [ecb, cbc] [plaintext.(txt, bmp)]")
        return

    # check if input file is a bitmap file
    # if it is a bmp file, strip the header
    bmp_input = False
    try:
        input_file = open(sys.argv[2], "rb")
    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print(f"An error occured: {e}")
    if sys.argv[2].endswith(".bmp"):
        bmp_input = True
        bmp_header = read_bmp_header(input_file)
    
    # get pointers to output file
    if bmp_input:
        output_file = write_bmp_header(bmp_header)
    else:
        try:
            output_file = open("encrypted.txt", "wb")
        except Exception as e:
            print(f"An error occured: {e}")

    # generate key and cipher
    key = generate_key()
    cipher = AES.new(key, AES.MODE_ECB)
    if sys.argv[1] == "cbc":
        iv = get_random_bytes(block_size)

    # ecb mode
    if sys.argv[1] == "ecb":
        while True:
            block = get_block(input_file)
            if not block:
                break
            ciphertext = cipher.encrypt(block)
            output_file.write(ciphertext)

        output_file.close()
        return
    # cbc mode
    elif sys.argv[1] == "cbc":
        while True:
            block = get_block(input_file)
            if not block:
                break
            iv_as_int = int.from_bytes(iv, byteorder="big")
            block_as_int = int.from_bytes(block, byteorder="big")
            xored_int = iv_as_int ^ block_as_int
            xored_block = xored_int.to_bytes(block_size, byteorder="big")
            ciphertext = cipher.encrypt(xored_block)
            iv = ciphertext
            output_file.write(ciphertext)
        output_file.close()
        return
    return

def get_block(file):
    # read a block from the file, pad if it does not reach block size
    block = file.read(block_size)
    # check if we reached end
    if len(block) == 0:
        file.close()
        return None
    # check if block needs padding
    if len(block) != block_size:
        block = pkcs7_pad(block, block_size)
    return block

def pkcs7_pad(block, block_size):
    bytes_missing = block_size - len(block)
    return block + bytes([bytes_missing] * bytes_missing)

def generate_key():
    key = get_random_bytes(key_length)
    try:
        key_file = open("key.txt", "wb")
        key_file.write(key)
        key_file.close()
    except Exception as e:
        print(f"An error occured: {e}")
    return key

def read_bmp_header(input_file):
# strip header and save it
    bmp_header = None
    try:
        bmp_header = input_file.read(bmp_header_size)
    except Exception as e:
        print(f"An error occured: {e}")
    return bmp_header

def write_bmp_header(bmp_header):
    try:
        output_file = open("encrypted.bmp", "wb")
        output_file.write(bmp_header)
    except Exception as e:
        print(f"An error occured: {e}")
    return output_file

if __name__ == "__main__":
    main()