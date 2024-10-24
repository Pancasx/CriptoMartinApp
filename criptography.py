
import os
import json
from json_pathh import data_file
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

''' Funciones de cifrado y descifrado '''
# Funcion para crear el resumen de la contraseña
def hash(contraseña):
    # Generar un salt aleatorio
    salt_random = os.urandom(16)
    # Derivar la clave a partir de la contraseña y el salt
    kdf = Scrypt(
        salt=salt_random,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    # convertir la clave y el salt a hex
    clave_d = kdf.derive(bytes(contraseña, "utf-8"))
    clave = clave_d.hex()
    salt = salt_random.hex()
    return salt, clave

# Funcion para verificar que el usuario y la contraseña son correctos
def verify_hash(username, contraseña):
    # Obtener el salt y la contraseña del usuario
    salt, contra = get_user_salt_pw(username)
    # Convertir el salt y la contraseña a bytes
    salt_b = bytes.fromhex(salt)
    contra_b = bytes.fromhex(contra)
    # derivar la clave a partir de la contraseña y el salt
    kdf = Scrypt(
        salt=salt_b,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    kdf.verify(bytes(contraseña, "utf-8"), contra_b)
    return salt, contra

# Funcion para devolver el salt y el resumen de la contraseña
def get_user_salt_pw(username):
    with open(data_file, "r", encoding="utf-8", newline="") as df:
        temp = json.load(df)
    for key in temp:
        if username == key["Nombre"]:
            return key["Salt"], key["Clave"]
    raise Exception("El usuario no existe")

def insert_data(username, salt, hash, investments, Nonce):
    item_data = {}
    try:
        with open(data_file, "r", encoding="utf-8", newline="") as df:
            temp = json.load(df)
    except FileNotFoundError:
        temp = []

    item_data["Nombre"] = username
    item_data["Clave"] = hash
    # Diccionario con las criptomonedas y transacciones
    item_data["Inversiones"] = investments  
    item_data["Salt"] = salt
    item_data["Nonce"] = Nonce
    temp.append(item_data)
    
    with open(data_file, "w") as df:
        json.dump(temp, df, indent=3)

"""Funcion para agregar un libro al fichero json"""
def insert_cripto(username, cripto, cantidad, valor, pw):
    item_data = {}
    
    # Derivar una clave a partir de la contraseña
    salt, clave_hex = hash(pw)

    # Convertir la clave de hexadecimal a bytes
    clave = bytes.fromhex(clave_hex)

    # Crear una instancia de ChaCha20Poly1305 con la clave derivada
    chacha = ChaCha20Poly1305(clave)

    # Generar un nonce aleatorio
    nonce = os.urandom(12)

    # Convertir la información de criptomoneda en un mensaje para cifrar
    mensaje = f"{cripto},{cantidad},{valor}".encode("utf-8")

    # Cifrar el mensaje
    cifrado = chacha.encrypt(nonce, mensaje, None)

    with open(data_file, "r", encoding="utf-8", newline="") as df:
         temp = json.load(df)
    for i in range(len(temp)):
        diccionario = temp[i]
        if diccionario["Nombre"] == username:
            item_data = temp.pop(i)
            item_data["Inversiones"][cripto] = {
                "cifrado": cifrado.hex(),  # Almacenar el cifrado en hexadecimal
                "nonce": nonce.hex(),  # Almacenar el nonce
                "salt": salt  # Almacenar el salt usado para derivar la clave
            }
            break
    
    temp.append(item_data)
    with open(data_file, "w") as df:
        json.dump(temp, df, indent=3)

    descifrado = chacha.decrypt(nonce, cifrado, None)
    return descifrado.decode("utf-8")
