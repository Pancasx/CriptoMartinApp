
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, SubjectAlternativeName, DNSName
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

''' Certificados '''
# Función para verificar la clave pública con el certificado de la CA
def verificar_clave_publica_con_ca(ca_certificate, clave_publica_firmada_ca):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.exceptions import InvalidSignature
    print("PROCESO DE VERIFICACIÓN DE CLAVE PÚBLICA FIRMADA CON CERTIFICADO SUBORDINADO:")
    print("-------------------------------------------------------")
    try:
        # Cargar el certificado firmado de la clave pública
        certificado_usuario = x509.load_pem_x509_certificate(clave_publica_firmada_ca)

        # Verificar que el certificado fue emitido por la CA
        ca_certificate.public_key().verify(
            certificado_usuario.signature,
            certificado_usuario.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificado_usuario.signature_hash_algorithm,
        )

        # Verificar que el certificado no ha expirado
        if certificado_usuario.not_valid_before <= datetime.utcnow() <= certificado_usuario.not_valid_after:
            return True
        else:
            print("Advertencia: El certificado de la clave pública ha expirado o no es válido aún.")
            return False

    except InvalidSignature:
        print("Advertencia: La firma del certificado no coincide.")
        return False
    except Exception as e:
        print(f"Error al verificar el certificado: {e}")
        return False
    print("-------------------------------------------------------")
# Función para firmar la clave pública con el certificado de la CA subordinada
def firmar_clave_publica(correo, clave_publica_pem, ca_private_key, ca_certificate):
    print("PROCESO DE FIRMADO DE CLAVE PÚBLICA USUARIO CON CERTIFICADO SUBORDINADO:")
    print("-------------------------------------------------------")
    # Crear el certificado para la clave pública del usuario
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, correo),
    ])
    issuer = ca_certificate.subject  # La autoridad subordinada firma el certificado

    certificado_usuario = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(serialization.load_pem_public_key(clave_publica_pem))
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Certificado válido por 1 año
        .sign(ca_private_key, hashes.SHA256())
    )
    print(certificado_usuario)
    print("-------------------------------------------------------")

    return certificado_usuario.public_bytes(encoding=serialization.Encoding.PEM)

# Función para cargar un certificado desde un archivo
def cargar_certificado(nombre_archivo):
    try:
        with open(nombre_archivo, "rb") as archivo_certificado:
            certificado_pem = archivo_certificado.read()
        certificado = load_pem_x509_certificate(certificado_pem)
        print("-------------------------------------------------------")
        print(f"Certificado cargado exitosamente desde {nombre_archivo}.")
        print("-------------------------------------------------------")
        return certificado
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {nombre_archivo}.")
        return None
    except Exception as e:
        print(f"Error al cargar el certificado: {e}")
        return None
# Función para cargar una clave privada desde un archivo
def cargar_clave_privada(nombre_archivo, password=None):
    try:
        with open(nombre_archivo, "rb") as archivo_clave_privada:
            clave_privada_pem = archivo_clave_privada.read()
        clave_privada = serialization.load_pem_private_key(
            clave_privada_pem,
            password=password.encode('utf-8') if password else None
        )
        print("-------------------------------------------------------")
        print(f"Clave privada cargada exitosamente desde {nombre_archivo}.")
        print("-------------------------------------------------------")
        return clave_privada
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {nombre_archivo}.")
        return None
    except Exception as e:
        print(f"Error al cargar la clave privada: {e}")
        return None
    
''' Firma Digital'''
# Función para firmar datos con la clave privada
def firmar_datos(clave_privada_pem, datos):
    print("PROCESO DE FIRMA DIGITAL:")
    print("-------------------------------------------------------")
    # Cargar la clave privada desde PEM
    clave_privada = serialization.load_pem_private_key(
        clave_privada_pem,
        password=None
    )
    print("Datos a firmar:")
    print(datos)

    # Obtener la longitud de la clave privada
    key_size = clave_privada.key_size
    print(f"Tipo de algoritmo: RSA con PSS y SHA-256")
    print(f"Longitud de la clave utilizada: {key_size} bits")

    # Firmar los datos con la clave privada
    firma = clave_privada.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )
    print(f"Firma generada con éxito: {firma.hex()}")
    print("-------------------------------------------------------")
    return firma

# Función para verificar la firma con la clave pública
def verificar_firma(clave_publica_pem, datos, firma):
    print("PROCESO DE VERIFICACIÓN DE FIRMA DIGITAL:")
    print("-------------------------------------------------------")
    # Cargar la clave pública desde PEM
    clave_publica = serialization.load_pem_public_key(clave_publica_pem)
    print("Datos a verificar:")
    print(datos)
    print("Firma a verificar:")
    print(firma.hex())

    # Obtener la longitud de la clave pública
    key_size = clave_publica.key_size
    print(f"Tipo de algoritmo: RSA con PSS y SHA-256")
    print(f"Longitud de la clave utilizada: {key_size} bits")
    
    # Verificar la firma
    try:
        clave_publica.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        print("La firma es válida.")
        print("-------------------------------------------------------")
        return True
    except InvalidSignature:
        print("La firma no es válida.")
        print("-------------------------------------------------------")
        return False
    except Exception as e:
        print(f"Error inesperado durante la verificación de la firma: {e}")
        print("-------------------------------------------------------")
        return False

''' Funciones de cifrado,descifrado y autenticación '''

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

