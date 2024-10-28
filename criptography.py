
import os
import json
import base64
import hashlib
from json_pathh import data_file
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

''' Funciones de cifrado y descifrado '''

#Función para crear par de claves asimétricas (pública y privada)
def generar_par_de_claves():
    print("PROCESO DE GENERACIÓN CLAVES PÚBLICA Y PRIVADA:")
    print("-------------------------------------------------------")
    print("Clave pública: Almacenada y encriptada en DB")
    print("Clave privada: Almacenada en el ordenador del usuario sin encriptar")
    print("USANDO RSA generamos claves")
    clave_privada = rsa.generate_private_key(
        public_exponent=65537, #Nímero comun para generar claves por ser primo y más eficiente.
        key_size=2048,
    )
    print(f"CLAVE PRIVADA GENERADA:{clave_privada}")
    
    # Genero la clave pública a partir de la privada
    clave_publica = clave_privada.public_key()
    print(f"CLAVE PUBLICA GENERADA:{clave_publica}")

    # Serialización de las claves en formato PEM (Se serializa para poder transmitir o guardar)
    clave_privada_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM, #PEM códifica datos binerios en ASCII
        format=serialization.PrivateFormat.PKCS8, #Estándar de almacenamiento claves privadas
        encryption_algorithm=serialization.NoEncryption()#No la ciframos porque la privada se va a guardar en el ordenador del usuario
    )
    
    clave_publica_pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("¡Par de claves generadas con éxito!")
    print("-------------------------------------------------------")
    return clave_privada_pem, clave_publica_pem

# Función para cifrar datos con la clave pública del usuario
def cifrar_con_clave_publica(clave_publica_pem, datos):
    print("PROCESO DE CIFRADO CON CLAVE PÚBLICA:")
    print("-------------------------------------------------------")
    # Cargar la clave pública desde PEM
    clave_publica = serialization.load_pem_public_key(clave_publica_pem)
    print("Datos a cifrar:")
    print(datos)

    # Cifrar los datos usando la clave pública
    datos_cifrados = clave_publica.encrypt(
        datos,
        padding.OAEP( #OAEP combina entrada con cadena aleatoria, produce textos cifrados diferentes cada vez
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"¡Datos cifrados con éxito!: {datos_cifrados}")
    print("-------------------------------------------------------")
    # Codificar los datos cifrados en base64 para almacenarlos o transmitirlos más fácilmente
    return base64.b64encode(datos_cifrados)

def descifrar_con_clave_privada(ruta_clave_privada, datos_cifrados):
    try:
        # Verifico si la ruta de la clave privada existe
        if not os.path.exists(ruta_clave_privada):
            print(f"Error: La ruta de la clave privada '{ruta_clave_privada}' no existe.")
            return None
        
        print(f"Cargando la clave privada desde: {ruta_clave_privada}")
        
        # Cargo la clave privada
        with open(ruta_clave_privada, 'rb') as archivo_privado:
            clave_privada = serialization.load_pem_private_key(
                archivo_privado.read(),
                password=None
            )

        # Decodifico los datos cifrados
        try:
            datos_cifrados = base64.b64decode(datos_cifrados)
        except Exception as e:
            print(f"Error al decodificar los datos cifrados: {e}")
            return None

        print(f"Datos cifrados: {datos_cifrados}")  # Mostrar datos cifrados para depuración
        
        # Descifro los datos usando la clave privada
        try:
            datos_descifrados = clave_privada.decrypt(
                datos_cifrados,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError as e:
            print(f"Error durante el descifrado: {e}")
            return None

        if not isinstance(datos_descifrados, bytes):
            print("Error: Los datos descifrados no son del tipo esperado (bytes).")
            return None

        return datos_descifrados
    
    except Exception as e:
        print(f"Se produjo un error: {e}")
        return None
    
# Función para hashear la contraseña
def hash_password(password):
    print("PROCESO DE GENERAR HASH PARA PASSWORD NUEVA:")
    print("-------------------------------------------------------")
    print("Algoritmo de hash utilizado: PBKDF2-HMAC con SHA-256")
    print(f"Longitud de la contraseña ingresada: {len(password)} caracteres")
    
    salt = os.urandom(16)
    print(f"Salt generado (16 bytes): {salt}")

    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    print("Operación de hash realizada con 100000 iteraciones")

    encoded_salt = base64.b64encode(salt).decode('utf-8')
    encoded_hashed_pw = base64.b64encode(hashed_pw).decode('utf-8')
    print(f"Salt en Base64: {encoded_salt}")
    print(f"Contraseña hasheada en Base64: {encoded_hashed_pw}")
    print("-------------------------------------------------------")

    return encoded_salt, encoded_hashed_pw

#Función para hasherar contraseña con un salt dado (Para verificar una contraseña)

def hash_password_salt(password, salt):
    print("PROCESO DE GENERAR HASH CON SALT DADO:")
    print("-------------------------------------------------------")
    print(f"Salt DB: {salt}")

    salt = base64.b64decode(salt.encode('utf-8'))
    print(f"Salt decodificado (binario): {salt}")

    print("Algoritmo de hash utilizado: PBKDF2-HMAC con SHA-256")
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000) #100K Iteraciones
    print("Operación de hash realizada con pass externa y 100,000 iteraciones")
    print(f"Hashed Password Externa: {hashed_pw}")
    print("-------------------------------------------------------")
    return base64.b64encode(hashed_pw).decode('utf-8')

''' Funciones para autenticacion '''
# Función para crear un MAC usando ChaCha20Poly1305 con depuración
def crear_mac_chacha20poly1305(llave, nonce, mensaje):
    print("GENERANDO MAC CON ChaCha20Poly1305")
    print("-----------------------------------------")
    print(f"Tipo de algoritmo: ChaCha20Poly1305")
    print(f"Longitud de clave: {len(llave) * 8} bits")  # longitud en bits
    print(f"Nonce usado: {nonce.hex()}")
    chacha = ChaCha20Poly1305(llave)
    mac = chacha.encrypt(nonce, mensaje, None)
    print(f"MAC generado con exito!: {mac.hex()}")
    print("-----------------------------------------")
    return mac

# Función para verificar el MAC con mensajes de depuración
def verificar_mac_chacha20poly1305(llave, nonce, mensaje, mac):
    print("VERIFICANDO MAC CON ChaCha20Poly1305")
    print("-----------------------------------------")
    print(f"Tipo de algoritmo: ChaCha20Poly1305")
    print(f"Longitud de clave: {len(llave) * 8} bits")
    print(f"Nonce usado: {nonce.hex()}")
    chacha = ChaCha20Poly1305(llave)
    try:
        chacha.decrypt(nonce, mac, None)
        print("Verificación de MAC con exito: El mensaje es auténtico.")
        print("-----------------------------------------")
        return True
    except Exception as e:
        print(f"Error de verificación de MAC: {e}")
        print("La verificación falló: El mensaje puede haber sido alterado.")
        print("-----------------------------------------")
        return False

