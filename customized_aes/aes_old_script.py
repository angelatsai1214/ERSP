from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from base64 import b64encode

# Source: https://stackoverflow.com/questions/67517456/python-how-to-decode-aes-encrypt-encoded-cipher-texts
import base64

def base64Decoding(input):
  return b64encode(input).decode('utf-8')

def asciiDecoding(input): # gets error
    return base64.decodebytes(input.encode("ascii"))





print("========CBC========")

cbc_key = get_random_bytes(16)
cbc_data = b'secret cbc_data'

cbc_nonce = get_random_bytes(13)
cmd_len_byte = len(cbc_data).to_bytes(2,byteorder="big")

cbc_encrypt_cmd = pad(int.to_bytes(25) + cbc_nonce + cmd_len_byte + cbc_data, AES.block_size)

cipher = AES.new(cbc_key, AES.MODE_CBC)
cipher_text = cipher.encrypt(cbc_encrypt_cmd)

iv = bytes(16) # --cipher.iv-- for our case we want iv to be 16 of byte 0

print("cipher_text: ", cipher_text, ' -> ', base64Decoding(cipher_text))

decrypt_cipher = AES.new(cbc_key, AES.MODE_CBC, iv)
plain_text = unpad(decrypt_cipher.decrypt(cipher_text),AES.block_size)

print("final_text: ", plain_text)

print()
print("========CTR========")




# CTR


ctr_key = get_random_bytes(16)
ctr_data = b'secret ctr_data'
ctr_n = get_random_bytes(13)

ctr_counter = Counter.new(128, little_endian=False, initial_value=int.from_bytes(b'\x01'+ctr_n+b'\x0001','big') % (1 << 128))
# was getting Initial value takes 129 bits but it is longer than the counter (128 bits) 
# so added bit shifting, not sure why it was 129 bits though

cipher = AES.new(ctr_key, AES.MODE_CTR, nonce=None, counter=ctr_counter)
cipher_text = cipher.encrypt(ctr_data)
# nonce = cipher.nonce

print("cipher_text: ", cipher_text, ' -> ', base64Decoding(cipher_text))
# print("nonce: ", nonce)
# make nounce just a byte of 01
# make counter n that we find later, and then 0001 at the end
# add a vairable for "byte_encoding"
# l = len(cmd)
# l.to_bytes(2, byteorder="little")  not sure if lock does big or little endian
# 25 also need to be encoded as a byte

decrypt_cipher = AES.new(ctr_key, AES.MODE_CTR, nonce=None, counter=ctr_counter)
plain_text = decrypt_cipher.decrypt(cipher_text)

print("final_text: ", plain_text)


