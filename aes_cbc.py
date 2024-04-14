from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = get_random_bytes(16)
data = b'secret data'

# CBC
cipher = AES.new(key, AES.MODE_CBC)
cipher_text = cipher.encrypt(pad(data, AES.block_size))
iv = cipher.iv

decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
plain_text = decrypt_cipher.decrypt(cipher_text)


# CTR
# cipher = AES.new(key, AES.MODE_CTR)
# cipher_text = cipher.encrypt(data)
# nonce = cipher.nonce

# decrypt_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
# plain_text = decrypt_cipher.decrypt(cipher_text)