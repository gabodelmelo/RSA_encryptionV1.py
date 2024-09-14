# pip install Crypto
 
import io
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def key_generator():

# Generate pair of RSA key of 3072 bits 
    key = RSA.generate(3072)

# Passphrase to encrypt the private key
    #username = input("Introduce your username: ")
    secret_code = input("Create a password: ")

# Export private key
    private_key = key.export_key(passphrase=secret_code)

# save the private key on a file
    with open("private.pem", "wb") as f:
        f.write(private_key)

# get the public key
    public_key = key.publickey().export_key()

# save the public key on a file
    with open("public.pem", "wb") as f:
        f.write(public_key)


def cipher():

# encrypt message with utf-8
    cadena = input("Message: ")
    bin_data = cadena.encode("utf-8")

# read the file with public key
    with open("public.pem", "rb") as f:
        recipient_key = f.read()

# import the public key
    key = RSA.importKey(recipient_key)

# asymetric cipher
    cipher_rsa = PKCS1_OAEP.new(key)

# generate a key for the cipher
    aes_key = get_random_bytes(16)

# encrypt the key of the simetric cypher with public RSA key
    enc_aes_key = cipher_rsa.encrypt(aes_key)

# encrypt the data with simetric cipher
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(bin_data)

#Concatenate the encrypted symmetric key to the data encrypted with it
    enc_data = b"".join((enc_aes_key, cipher_aes.nonce, tag, ciphertext))
    return enc_data


def decipher(enc_data):
# emulate a file with our string because the read method facilitates the division of each part of the string (data and encrypted AES key).
    data_file = io.BytesIO(enc_data)

# read the file with the private key
    with open("private.pem", "rb") as f:
        recipient_key = f.read()

    passphrase = input("Password: ")

# We load the public key (RSA class instance)
    key = RSA.importKey(recipient_key,  passphrase)

# Asymmetric cipher instance
    cipher_rsa = PKCS1_OAEP.new(key)

# Separate the different parts of the encrypted string
    enc_aes_key, nonce, tag, ciphertext =\
        (data_file.read(c) for c in (key.size_in_bytes(), 16, 16, -1))

# We decrypt the AES key using the RSA private key.
    aes_key = cipher_rsa.decrypt(enc_aes_key)

# We decrypt the data itself using the AES key
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    cadena = data.decode("utf-8")
    print(cadena)



print(key_generator())

enc_data = cipher()

print(decipher(enc_data))
