from Crypto.Random import get_random_bytes
from base64 import b64encode

from aes_encrypt_pipeline import cmdEnc
from aes_decrypt_pipeline import parseAndDecCmdResp

def base64Decoding(input):
  return b64encode(input).decode('utf-8')


key = get_random_bytes(16)
command = b'open lock'
nonce = get_random_bytes(13)
cmd_encrypted = cmdEnc(key,nonce,command)
print(cmd_encrypted, ' -> ', base64Decoding(cmd_encrypted))

tag = cmd_encrypted[-16:-8] # is this right size?

cmd_decrypted = parseAndDecCmdResp(key,nonce,cmd_encrypted,tag)