from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
import sys


def get_ec_key(subject, pub_path, priv_path):
    complete_key = ECC.generate(curve='P-256')
    pub_key = complete_key.public_key().export_key(format='PEM')
    priv_key = complete_key.export_key(format='PEM')

    pub_file = open(pub_path, "w")
    pub_file.write(subject + '\n')
    pub_file.write('ECC\n')
    pub_file.write(pub_key)
    pub_file.close()

    priv_file = open(priv_path, "w")
    priv_file.write(subject + '\n')
    priv_file.write('ECC\n')
    priv_file.write(priv_key)
    priv_file.close()


def get_rsa_key(subject, pub_path, priv_path):
    complete_key = RSA.generate(2048)
    pub_key = complete_key.publickey().exportKey("PEM")
    priv_key = complete_key.exportKey("PEM")

    # print(pub_key)
    pub_file = open(pub_path, "w")
    pub_file.write(str(subject) + '\n')
    pub_file.write('RSA' + '\n')
    pub_file.write(str(pub_key, 'utf-8') + '\n')
    pub_file.close()

    priv_file = open(priv_path, "w")
    priv_file.write(str(subject) + '\n')
    priv_file.write('RSA' + '\n')
    priv_file.write(str(priv_key, 'utf-8') + '\n')
    priv_file.close()


# need to wrap it in command line stuff, and give rsa vs ec option

sub = "Michaela"
pub_f_name = "pubkey_ec.txt"
priv_f_name = "privkey_ec.txt"

if len(sys.argv) != 9:
    print('usage: keygen -t <type of key pair> -s <subject> -pub <path to public key file> -priv <paht to private key file>')
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
    print('usage: keygen -t <type of key pair> -s <subject> -pub <path to public key file> -priv <paht to private key file>')
    exit()

if sys.argv[1] == '-pub':
    pub_f_name = sys.argv[2]
elif sys.argv[3] == '-pub':
    pub_f_name = sys.argv[4]
elif sys.argv[5] == '-pub':
    pub_f_name = sys.argv[6]
elif sys.argv[7] == '-pub':
    pub_f_name = sys.argv[8]
else:
    print('usage: keygen -t <type of key pair> -s <subject> -pub <path to public key file> -priv <paht to private key file>')
    exit()

if sys.argv[1] == '-priv':
    priv_f_name = sys.argv[2]
elif sys.argv[3] == '-priv':
    priv_f_name = sys.argv[4]
elif sys.argv[5] == '-priv':
    priv_f_name = sys.argv[6]
elif sys.argv[7] == '-priv':
    priv_f_name = sys.argv[8]
else:
    print('usage: keygen -t <type of key pair> -s <subject> -pub <path to public key file> -priv <paht to private key file>')
    exit()

key_type = "ec"
if sys.argv[1] == '-t':
    key_type = sys.argv[2]
elif sys.argv[3] == '-t':
    key_type = sys.argv[4]
elif sys.argv[5] == '-t':
    key_type = sys.argv[6]
elif sys.argv[7] == '-t':
    key_type = sys.argv[8]
else:
    print('usage: keygen -t <type of key pair> -s <subject> -pub <path to public key file> -priv <paht to private key file>')
    exit()



if key_type == "rsa":
    get_rsa_key(sub, pub_f_name, priv_f_name)

if key_type == "ec":
    get_ec_key(sub, pub_f_name, priv_f_name)
