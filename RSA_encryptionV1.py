import io
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def key_generator():

# Generar pareja de claves RSA de 3072 bits de longitud
    key = RSA.generate(3072)

# Passphrase para encriptar la clave privada
    #username = input("Introduce your username: ")
    secret_code = input("Create a password: ")

# Exportamos la clave privada
    private_key = key.export_key(passphrase=secret_code)

#Guardamos la clave privada en un fichero
    with open("private.pem", "wb") as f:
        f.write(private_key)

#Obtenemos la clave pública
    public_key = key.publickey().export_key()

#Guardamos la clave pública en otro fichero
    with open("public.pem", "wb") as f:
        f.write(public_key)


def cipher():

#encriptar mensaje utf-8
    cadena = input("Message: ")
    bin_data = cadena.encode("utf-8")

#Leemos el archivo con la clave publica
    with open("public.pem", "rb") as f:
        recipient_key = f.read()

#Cargamos la clave pública (instancia de clase RSA)
    key = RSA.importKey(recipient_key)

#cifrador asimétrico
    cipher_rsa = PKCS1_OAEP.new(key)

#Generamos una clave para el cifrado simétrico
    aes_key = get_random_bytes(16)

#Encriptamos la clave del cifrado simétrico con la clave pública RSA
    enc_aes_key = cipher_rsa.encrypt(aes_key)

#Encriptamos los datos mediante cifrado simétrico (AES en este caso)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(bin_data)

#Concatenamos la clave simétrica cifrada a los datos cifrados con ella
    enc_data = b"".join((enc_aes_key, cipher_aes.nonce, tag, ciphertext))
    return enc_data


def decipher(enc_data):
#Emulamos un fichero con nuestra cadena porque el método read facilita la división de cada parte de la cadena (datos y clave AES encriptada).
    data_file = io.BytesIO(enc_data)

#Leemos el archivo con la clave privada
    with open("private.pem", "rb") as f:
        recipient_key = f.read()

    passphrase = input("Introduce tu contraseña: ")

#Cargamos la clave pública (instancia de clase RSA)
    key = RSA.importKey(recipient_key,  passphrase)

#Instancia del cifrador asimétrico
    cipher_rsa = PKCS1_OAEP.new(key)

#Separamos las distintas partes de la cadena cifrada
    enc_aes_key, nonce, tag, ciphertext =\
        (data_file.read(c) for c in (key.size_in_bytes(), 16, 16, -1))

#Desencriptamos la clave AES mediante la clave privada RSA
    aes_key = cipher_rsa.decrypt(enc_aes_key)

#Desencriptamos los datos en si con la clave AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    cadena = data.decode("utf-8")
    print(cadena)



print(key_generator())

enc_data = cipher()

print(decipher(enc_data))
