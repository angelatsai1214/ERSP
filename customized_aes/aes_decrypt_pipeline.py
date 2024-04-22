from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from base64 import b64encode

def base64Decoding(input):
  return b64encode(input).decode('utf-8')

def CTR_DEC(key, n, c_m):
    ctr_counter = Counter.new(128, little_endian=False, initial_value=int.from_bytes(b'\x01'+n+b'\x0001','big') % (1 << 128))
    decrypt_cipher = AES.new(key, AES.MODE_CTR, nonce=None, counter=ctr_counter)
    decrypt_text = decrypt_cipher.decrypt(c_m)

    print("ctr_decrypt_text: ", base64Decoding(decrypt_text))
    
    return decrypt_text


def CBC_DEC(key, m_encoded):
    iv = bytes(16) 

    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypt_text = decrypt_cipher.decrypt(m_encoded)
    # decrypt_text = unpad(decrypt_cipher.decrypt(m_encoded),AES.block_size)

    print("cbc_final_text: ", base64Decoding(decrypt_text))
    
    return decrypt_text
    
    
def parseAndDecCmdResp(key,nonce,c_resp, tag):
    
    length = c_resp[0] << 8 | c_resp[1]
    C1 = c_resp[2:length + 2]
    C2 = c_resp[length + 2]
    
    print("c_resp: ", base64Decoding(c_resp))
    print("length: ", length)
    print("C1: ",base64Decoding(C1))
    print("C2: ",C2)
    
    # don't pass these
    # if len(c_resp) < 10 or len(c_resp) < length or C1 != length: 
    #     print("cipher length error")
    #     return
    
    # if C2 != 8:
    #     print("mac length error")
    #     return
    
    C1_padded = pad(C1,AES.block_size)
    m = CBC_DEC(key,C1_padded)
    m_len_byte = len(m).to_bytes(2,byteorder="big")
    m_encoded = pad(int.to_bytes(25) + nonce + m_len_byte + m, AES.block_size)
    
    t_n = CTR_DEC(key,nonce,tag) # C2 and tag same?? C2 is an integer though, raises error, cants to len(integer)
    
    c_tag = CBC_DEC(key,m_encoded)
    
    # doesn't pass this either
    # if t_n != c_tag[-16:-8]:
    #     print("mac verify error")
    #     return
    
    return m
    
    
    
    
    
    
    
    
    
