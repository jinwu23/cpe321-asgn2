import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

block_size = 16 # 16 bytes (128 bits) 
bmp_header_size = 54 # 54 bytes
key_length = 16 # 16 byte key

def main():
    if len(sys.argv) != 2:
        print("Please input a single file")
        return
    
    # check if input file is a bitmap file
    # if it is a bmp file, strip the header
    bmp_input = False
    if sys.argv[1].endswith(".bmp"):
        bmp_input = True
        # strip header and save it
        try:
            input_file = open(sys.argv[1], "rb")
            bmp_header = input_file.read(bmp_header_size)
        except Exception as e:
            print(f"An error occured: {e}")
    else:
        # get pointers to input file
        try:
            input_file = open(sys.argv[1], "rb")
        except FileNotFoundError:
            print("File not found")
        except Exception as e:
            print(f"An error occured: {e}")
    
    # get pointers to output file
    if bmp_input:
        try:
            output_file = open("encrypted.bmp", "wb")
            output_file.write(bmp_header)
        except Exception as e:
            print(f"An error occured: {e}")
    else:
        try:
            output_file = open("encrypted.txt", "wb")
        except Exception as e:
            print(f"An error occured: {e}")

    # generate key and cipher
    key = get_random_bytes(key_length)
    try:
        key_file = open("key.txt", "wb")
        key_file.write(key)
        key_file.close()
        print(f"generated key is in key.txt")
    except Exception as e:
        print(f"An error occured: {e}")
    cipher = AES.new(key, AES.MODE_ECB)

    # read blocks from file
    while True:
        block = get_block(input_file)
        if not block:
            break
        ciphertext = cipher.encrypt(block)
        output_file.write(ciphertext)

    output_file.close()
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
        block = pad(block, block_size, "pkcs7")
    return block

if __name__ == "__main__":
    main()