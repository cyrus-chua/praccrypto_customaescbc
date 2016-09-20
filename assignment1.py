from Crypto.Util.strxor import strxor_c, strxor
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA
import hashlib
import hmac
import math
import argparse

def hmac_sha1(k_mac_16, m):
    ipad = 0x36
    opad = 0x5C
    k_16bytes = k_mac_16
    k_64bytes_padded = k_16bytes + str('\x00' * (64-len(k_16bytes)))
    #print k_64bytes_padded.encode('hex')
    outer = strxor_c(k_64bytes_padded, opad)
    #print outer.encode('hex')
    inner = strxor_c(k_64bytes_padded, ipad)
    #print inner.encode('hex')
    #hash(outer || hash(inner || message))
    h1 = hashlib.sha1(inner+m).digest()
    #xh1 = SHA.new(inner+m).digest()
    #print h1.encode('hex'), xh1.encode('hex')
    h2 = hashlib.sha1(outer+h1).digest()
    #xh2 = SHA.new(outer+h1).digest()
    #print h2.encode('hex'), xh2.encode('hex')
    return h2

def breakinto_16byte_blocks(inputstring_multipleof_16):
    size = len(inputstring_multipleof_16)
    #print "size", size
    output_list = []
    if size == 16:
        output_list.append(inputstring_multipleof_16)
        #print "no loop"
    else:
        #print "yes loop"
        for i in range(1, size/16+1):
            x = i * 16
            w = (i-1) * 16
            output_list.append(inputstring_multipleof_16[w:x])
    #print output_list
    return output_list

def combinefrom_16byte_chunks(inputlist_16byte_chunks):
    output_string = ""
    for x in inputlist_16byte_chunks:
        output_string+=x
    return output_string

def aes_cbc_enc(k, iv, m):
    m2_blocks = breakinto_16byte_blocks(m)
    #print "m", m.encode("hex")
    #print m2_blocks
    ciphertext_blocks = []
    curr_block_input = ""
    curr_block_iv = iv
    current_block_num = 0
    aes_obj_ecb = AES.new(k, AES.MODE_ECB)
    for block in m2_blocks:
        #print "currently encrypting this block", block.encode("hex")
        curr_block_input = strxor(curr_block_iv, block)
        #alternative way to xor ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(prev_block_output, block))
        curr_block_output = aes_obj_ecb.encrypt(curr_block_input)
        ciphertext_blocks.append(curr_block_output)
        curr_block_iv = curr_block_output
        #print prev_block_output
        current_block_num+=1
    ciphertext = combinefrom_16byte_chunks(ciphertext_blocks)
    return ciphertext

def encrypt(k_enc, k_mac, m):
    hmac1 = hmac_sha1(k_mac, m)
    #print "hmac is", hmac1.encode("hex")
    m1 = m + hmac1
    #print "before padding", m1.encode("hex")
    n = len(m1)%16
    if n != 0:
        ps = bytes(bytearray([16-n]))*(16-n)
    if n == 0:
        ps = '\x10' * 16
    m2 = m1 + ps
    #print "after padding", m2.encode("hex"), "length", len(m2)
    random_generator = Random.new()
    iv = random_generator.read(16)
    #iv = "\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02"
    ciphertext = iv + aes_cbc_enc(k_enc, iv, m2)
    return ciphertext

def aes_cbc_dec(k, iv, c):
    c_blocks = breakinto_16byte_blocks(c)
    #print c.encode("hex")
    #print c_blocks
    plaintext_blocks = []
    curr_block_output = ""
    curr_block_iv = iv
    aes_obj_ecb = AES.new(k, AES.MODE_ECB)
    for block in c_blocks:
        #print "currently decrypting this block", block.encode("hex")
        #print "current block iv", curr_block_iv
        curr_block_output = aes_obj_ecb.decrypt(block)
        plaintext_blocks.append(strxor(curr_block_iv, curr_block_output))
        #alternative way to xor: ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(curr_block_output, curr_block_iv))
        curr_block_iv = block
    plaintext = combinefrom_16byte_chunks(plaintext_blocks)
    return plaintext

def verify_padding(padding):
    size = len(padding)
    for x in padding:
        if x != bytearray([size]):
            return 0
    return 1

def decrypt(k_dec, k_mac, c):
    #print "start"
    #print c
    #c = c.decode("hex")
    iv = c[0:16]
    c1 = c[16:]
    #print "iv and c1", iv.encode("hex"), c1.encode("hex")
    m2 = aes_cbc_dec(k_dec, iv, c1)
    #print "m2", m2.encode("hex")
    n = int(m2[-1].encode('hex'), 16)
    #print n
    m2_padding = m2[-n:]
    #print m2_padding
    if verify_padding(m2_padding) == 0:
        print "INVALID PADDING"
        return "0"
    m1 = m2[:-n]
    m = m1[:-20]
    t = m1[-20:]
    t1 = hmac_sha1(k_mac, m)
    if t != t1:
        print "INVALID MAC"
        return "0"
    return m

def main():
    parser = argparse.ArgumentParser(description='.')
    parser.add_argument('mode', help='.')
    parser.add_argument('-k', help='has to be in hex')
    parser.add_argument('-i', help='.')
    parser.add_argument('-o', help='.')

    args = parser.parse_args()
    mode = args.mode
    key = args.k.decode("hex")
    key_enc = key[:16]
    key_mac = key[16:]
    #print key.encode("hex"), key_enc.encode("hex"), key_mac.encode("hex")
    input_file = args.i
    output_file = args.o

    with open(input_file, 'rb') as infile:
        text = infile.read()
        if text[-1] == "\n":
            text = text[:-1]
        print text.encode("hex")

    if mode == "encrypt":
        cipher = encrypt(key_enc, key_mac, text)
        #print cipher.encode("hex")
        with open(output_file, 'wb') as outfile:
            outfile.write(cipher)
    elif mode == "decrypt":
        plaintext = decrypt(key_enc, key_mac, text)
        #print plaintext.encode("hex")
        with open(output_file, 'wb') as outfile:
            outfile.write(plaintext)
    else:
        print "wrong mode"

if __name__ == '__main__':
    main()