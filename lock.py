from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import PKCS1_OAEP
import sys
import os
from Crypto.Random import get_random_bytes


def make_AES_key(pub_key, priv_key, root_dir):

    # header = b"header"
    # data = b"secret"
    aes_key = get_random_bytes(16)

    # encrypt aes_key with rsa, and writing to file
    key = RSA.importKey(pub_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(aes_key)

    # adjust, use os.path join
    key_f_name = os.path.join(root_dir, "keyfile")
    key_file = open(key_f_name, "wb")
    key_file.write(ciphertext)
    key_file.close()

    # signing the key, and writing to file
    ec_key = ECC.import_key(priv_key)
    sig_hash = SHA256.new(ciphertext)
    signer = DSS.new(ec_key, 'fips-186-3')
    final_sig = signer.sign(sig_hash)

    key_f_name = os.path.join(root_dir, "keyfile.sig")
    sig_file = open(key_f_name, "wb")
    sig_file.write(final_sig)
    sig_file.close()

    return aes_key


def enc_all_files(aes_key, root_dir):
    # traverse directory, and encrypt and tag all regular files
    # my_cipher = AES.new(aes_key, AES.MODE_GCM)
    for dir_name, sub_dir_list, file_list in os.walk(root_dir):
        for f_name in file_list:
            # do the stuff, encrypt and the like
            # print('found ' + f_name + '\n')
            if f_name != 'keyfile' and f_name != 'keyfile.sig':
                # encrypt
                # change to os.path join
                my_cipher = AES.new(aes_key, AES.MODE_GCM)
                temp_name = os.path.join(dir_name, f_name)
                # print(temp_name)
                file_in = open(temp_name, 'r')
                data = file_in.read()
                file_in.close()
                temp_ciphertext, temp_tag = my_cipher.encrypt_and_digest(data.encode())

                # print(temp_ciphertext)
                file_out = open(temp_name, "wb")
                # file_out.write(my_cipher.nonce)
                # file_out.write(temp_tag)
                # file_out.write(temp_ciphertext)
                # file_out.close()
                [file_out.write(x) for x in (my_cipher.nonce, temp_tag, temp_ciphertext)]
                # print('encrypted ' + f_name + '\n')


# read in all command line items

pub_name = "pubkey.txt"
given_s = "Michaela"
root_d = "test"
priv_name = "privkey_ec.txt"

if len(sys.argv) != 9:
    print('usage: keygen -d <directory to lock> -p <public key of unlocking party> -r <private key to sign keyfile> -s <subject>')
    exit()

if sys.argv[1] == '-s':
    sub = sys.argv[2]
elif sys.argv[3] == '-s':
    sub = sys.argv[4]
elif sys.argv[5] == '-s':
    sub = sys.argv[6]
elif sys.argv[7] == '-s':
    sub = sys.argv[8]
else:
    print('usage: keygen -d <directory to lock> -p <public key of unlocking party> -r <private key to sign keyfile> -s <subject>')
    exit()

if sys.argv[1] == '-p':
    pub_name = sys.argv[2]
elif sys.argv[3] == '-p':
    pub_name = sys.argv[4]
elif sys.argv[5] == '-p':
    pub_name = sys.argv[6]
elif sys.argv[7] == '-p':
    pub_name = sys.argv[8]
else:
    print('usage: keygen -d <directory to lock> -p <public key of unlocking party> -r <private key to sign keyfile> -s <subject>')
    exit()

if sys.argv[1] == '-r':
    priv_name = sys.argv[2]
elif sys.argv[3] == '-r':
    priv_name = sys.argv[4]
elif sys.argv[5] == '-r':
    priv_name = sys.argv[6]
elif sys.argv[7] == '-r':
    priv_name = sys.argv[8]
else:
    print('usage: keygen -t <type of key pair> -s <subject> -pub <path to public key file> -priv <paht to private key file>')
    exit()

if sys.argv[1] == '-d':
    root_d = sys.argv[2]
elif sys.argv[3] == '-d':
    root_d = sys.argv[4]
elif sys.argv[5] == '-d':
    root_d = sys.argv[6]
elif sys.argv[7] == '-d':
    root_d = sys.argv[8]
else:
    print('usage: keygen -d <directory to lock> -p <public key of unlocking party> -r <private key to sign keyfile> -s <subject>')
    exit()

pub_key_file = open(pub_name, "r")
sub = pub_key_file.readline()
sub = sub[:-1]
# print(sub)
# print(given_s)
pb_s_type = pub_key_file.readline()
pb_key = pub_key_file.read()
pub_key_file.close()

priv_key_file = open(priv_name, "r")
pr_sub = priv_key_file.readline()
pr_s_type = priv_key_file.readline()
pr_key = priv_key_file.read()
priv_key_file.close()

if sub != given_s:
    print("Error, subject not correct\n")
    exit(1)

a_key = make_AES_key(pb_key, pr_key, root_d)

enc_all_files(a_key, root_d)
