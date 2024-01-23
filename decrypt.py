import sys
from Crypto.Cipher import AES

block_size = 16 # 16 bytes (128 bits) 
bmp_header_size = 54 # 54 bytes
key_length = 16 # 16 byte key

def main():
    if len(sys.argv) != 3:
        print("Please input an encrypted file and file containing key")
        return
    
    # get pointers to input file
    # check if input file is a bitmap file
    # if it is a bmp file, strip the header
    bmp_input = False
    if sys.argv[1].endswith(".bmp"):
        bmp_input = True
        # strip header and save it
        try:
            encrypted_file = open(sys.argv[1], "rb")
            bmp_header = encrypted_file.read(bmp_header_size)
        except Exception as e:
            print(f"An error occured: {e}")
    else:
        try:
            encrypted_file = open(sys.argv[1], "rb")
        except FileNotFoundError:
            print("File not found")
        except Exception as e:
            print(f"An error occured: {e}")
    
    
    # get pointers to output file
    if bmp_input:
        try:
            output_file = open("decrypted.bmp", "wb")
            output_file.write(bmp_header)
        except Exception as e:
            print(f"An error occured: {e}")
    else:
        try:
            output_file = open("decrypted.txt", "wb")
        except Exception as e:
            print(f"An error occured: {e}")

    # get key from file and get decipher
    key = get_key()
    decipher = AES.new(key, AES.MODE_ECB)

    # read blocks from file
    while True:
        # read a singular block
        block = encrypted_file.read(block_size)
        # check if we have read all blocks
        if len(block) == 0:
            encrypted_file.close()
            break
        # decrypt block
        decrypted_block = decipher.decrypt(block)
        if is_padded(decrypted_block):
            plaintext = pkcs7_unpad(decrypted_block)
        else:
            plaintext = decrypted_block
        output_file.write(plaintext)
    output_file.close()
    return

def is_padded(block):
    last_byte = block[-1]
    if block.endswith(bytes([last_byte]) * int(last_byte)):
        return True
    return False

def pkcs7_unpad(block):
    return block[:-block[-1]]

def get_key():
    try:
        key_file = open(sys.argv[2], "rb")
        key = key_file.read(key_length)
    except Exception as e:
        print(f"An error occured: {e}")
    return key

if __name__ == "__main__":
    main()