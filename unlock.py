from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import PKCS1_OAEP
import sys
import os

def check_keyfile_and_fetch_aes_key(root_dir, pub_name, priv_name, given_s):
    # checking the thing
    pub_key_file = open(pub_name, "r")
    sub = pub_key_file.readline()
    sub = sub[:-1]

    pb_s_type = pub_key_file.readline()
    pb_key = pub_key_file.read()
    pub_key_file.close()

    if(given_s != sub):
        print('Error: subject not correct')
        exit(1)



    priv_key_file = open(priv_name, "r")
    pr_sub = priv_key_file.readline()
    pr_s_type = priv_key_file.readline()
    pr_key = priv_key_file.read()
    priv_key_file.close()

    temp_f_name = os.path.join(root_dir, 'keyfile.sig')
    sig_file = open(temp_f_name, "rb")
    true_sig = sig_file.read()
    sig_file.close()

    temp_f_name = os.path.join(root_dir, 'keyfile')
    aes_file = open(temp_f_name, "rb")
    cipher_aes = aes_file.read()
    aes_file.close()
    ec_key = ECC.import_key(pb_key)
    temp_hash = SHA256.new(cipher_aes)
    verifier = DSS.new(ec_key, 'fips-186-3')

    try:
        verifier.verify(temp_hash, true_sig)
    except ValueError:
        print("The message is not authentic.")

    rsa_key = RSA.importKey(pr_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher.decrypt(cipher_aes)

    # delete keyfile and keyfile.sig
    temp_f_name = os.path.join(root_dir, 'keyfile')
    os.remove(temp_f_name)
    temp_f_name = os.path.join(root_dir, 'keyfile.sig')
    os.remove(temp_f_name)

    return(aes_key)


def decrypt_all_files(aes_key, root_dir):
    # decrypting all the files
    for dir_name, sub_dir_list, file_list in os.walk(root_dir):
        for f_name in file_list:
            # do the stuff, encrypt and the like
            if f_name != 'keyfile' and f_name != 'keyfile.sig':
                temp_name = os.path.join(dir_name, f_name)
                file_in = open(temp_name, "rb")
                nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
                file_in.close()
                # let's assume that the key is somehow available again
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
                data = cipher.decrypt(ciphertext)
                try:
                    cipher.verify(tag)
                except ValueError:
                    print("Key incorrect or message corrupted")
                    exit(1)

                file_out = open(temp_name, 'w')
                file_out.write(data.decode())
                file_out.close()



pub_name = "pubkey_ec.txt"
given_s = "Michaela"
root_d = "test"
priv_name = "privkey.txt"

if len(sys.argv) != 9:
    print('usage: unlock -d <directory to unlock> -p <public key of locking party> -r <private key to decrypt keyfile> -s <subject>')
    exit()

if sys.argv[1] == '-s':
    given_s = sys.argv[2]
elif sys.argv[3] == '-s':
    given_s = sys.argv[4]
elif sys.argv[5] == '-s':
    given_s = sys.argv[6]
elif sys.argv[7] == '-s':
    given_s = sys.argv[8]
else:
    print('usage: unlock -d <directory to unlock> -p <public key of locking party> -r <private key to decrypt keyfile> -s <subject>')
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
    print('usage: unlock -d <directory to unlock> -p <public key of locking party> -r <private key to decrypt keyfile> -s <subject>')
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
    print('usage: unlock -d <directory to unlock> -p <public key of locking party> -r <private key to decrypt keyfile> -s <subject>')
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
    print('usage: unlock -d <directory to unlock> -p <public key of locking party> -r <private key to decrypt keyfile> -s <subject>')
    exit()



aes_k = check_keyfile_and_fetch_aes_key(root_d, pub_name, priv_name, given_s)
decrypt_all_files(aes_k, root_d)
