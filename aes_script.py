from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


# Source: https://stackoverflow.com/questions/67517456/python-how-to-decode-aes-encrypt-encoded-cipher-texts
import base64

def base64Encoding(input):
  dataBase64 = base64.b64encode(input)
  dataBase64P = dataBase64.decode("UTF-8")
  return dataBase64P
def base64Decoding(input): # gets error
    return base64.decodebytes(input.encode("ascii"))

print("========CBC========")

cbc_key = get_random_bytes(16)
cbc_data = b'secret cbc_data'
print("cbc_data: ", cbc_data)

# CBC
cipher = AES.new(cbc_key, AES.MODE_CBC)
cipher_text = cipher.encrypt(pad(cbc_data, AES.block_size))
printable_cipher_text = base64Encoding(cipher_text)
# cipher_text = cipher.encrypt(cbc_data) # ValueError: Data must be padded to 16 byte boundary in CBC mode
iv = cipher.iv

print("cipher_text: ", cipher_text)
print("printable_cipher_text: ", printable_cipher_text)
print("iv: ", iv)

decrypt_cipher = AES.new(cbc_key, AES.MODE_CBC, iv)
plain_text = decrypt_cipher.decrypt(cipher_text)
# printable_decode_text = base64Decoding(plain_text)
print("decrypt_cipher: ", decrypt_cipher)
# print("printable_decode_text: ", printable_decode_text)
print("plain_text: ", plain_text)

print()
print("========CTR========")

# CTR
ctr_key = get_random_bytes(16)
ctr_data = b'secret ctr_data'

cipher = AES.new(ctr_key, AES.MODE_CTR)
cipher_text = cipher.encrypt(ctr_data)
nonce = cipher.nonce

print("cipher_text: ", cipher_text)
print("printable_cipher_text: ", printable_cipher_text)
print("nonce: ", nonce)


decrypt_cipher = AES.new(ctr_key, AES.MODE_CTR, nonce=nonce)
plain_text = decrypt_cipher.decrypt(cipher_text)

print("decrypt_cipher: ", decrypt_cipher)
print("plain_text: ", plain_text)


