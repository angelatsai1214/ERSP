from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from base64 import b64encode

def base64Decoding(input):
  return b64encode(input).decode('utf-8')


def CTR_ENC(key, n, data):

    ctr_counter = Counter.new(128, little_endian=False, initial_value=int.from_bytes(b'\x01'+n+b'\x0001','big') % (1 << 128))
    # was getting Initial value takes 129 bits but it is longer than the counter (128 bits) 
    # so added bit shifting, not sure why it was 129 bits though

    cipher = AES.new(key, AES.MODE_CTR, nonce=None, counter=ctr_counter)
    cipher_text = cipher.encrypt(data) # not sure if this is correct

    # print("ctr_cipher_text: ", cipher_text, ' -> ', base64Decoding(cipher_text))
    print("ctr_cipher_text: ", base64Decoding(cipher_text))
    
    return cipher_text
    
    
def CBC_ENC(key, cmd_encoded):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(cmd_encoded)

    # print("cbc_cipher_text: ", cipher_text, ' -> ', base64Decoding(cipher_text))
    print("cbc_cipher_text: ", base64Decoding(cipher_text))

    return cipher_text[-16:-8]
    

def cmdEnc(key, nonce, command):

    c_cmd = CTR_ENC(key, nonce, command)

    cmd_len_byte = len(command).to_bytes(2,byteorder="big")
    cmd_encoded = pad(int.to_bytes(25) + nonce + cmd_len_byte + command, AES.block_size)

    c_tag = CBC_ENC(key,cmd_encoded)

    tag = CTR_ENC(key, nonce, c_tag) # nonce update?? diff from prev??

    fully_encrypted = cmd_len_byte+c_cmd+tag
    
    return fully_encrypted



