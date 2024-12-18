import sqlite3
import os
import hashlib
import base64
from c_criptography import hash_password, generar_par_de_claves, cifrar_con_clave_publica,descifrar_con_clave_privada, hash_password_salt, crear_mac_chacha20poly1305, verificar_mac_chacha20poly1305, firmar_datos, verificar_firma, firmar_clave_publica, verificar_clave_publica_con_ca
from cryptography import x509
# Llave y nonce fijos para simplificación;
LLAVE_MAC = os.urandom(32)
NONCE = os.urandom(12)

# Función para crear la base de datos y las tablas
def crear_base_datos():
    if not os.path.exists("cryptomartin.db"):
        conn = sqlite3.connect("cryptomartin.db")
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correo TEXT UNIQUE,
                salt TEXT,
                hashed_pw TEXT,
                clave_publica TEXT,
                clave_publica_ca TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE transacciones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                datos_cifrados TEXT,
                mac TEXT,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        conn.commit()
        conn.close()

# Función para insertar un nuevo usuario
def insertar_usuario(correo, password, ca_private_key, ca_certificate):
    # Generar el salt y el hash de la contraseña
    salt, hashed_pw = hash_password(password)

    # Generar el par de claves al registrar
    clave_privada_pem, clave_publica_pem = generar_par_de_claves()

    # Crear firma de los datos del usuario
    datos_a_firmar = f"{correo}{hashed_pw}".encode('utf-8')
    firma = firmar_datos(clave_privada_pem, datos_a_firmar)

    # Concatenar la firma con la clave pública
    clave_publica_con_firma = clave_publica_pem + b"\nFIRMA\n" + firma

    # Guardar la clave privada en un archivo local
    ruta_clave_privada = f"./{correo}_privada.pem"  # Correo como nombre de archivo
    with open(ruta_clave_privada, 'wb') as archivo_privado:
        archivo_privado.write(clave_privada_pem)

    # Firmar la clave pública con la CA
    clave_publica_firmada_ca = firmar_clave_publica(correo, clave_publica_pem, ca_private_key, ca_certificate)

    # Guardar en la base de datos
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()

    # Insertar los datos en la base de datos
    cursor.execute(
        'INSERT INTO usuarios (correo, salt, hashed_pw, clave_publica, clave_publica_ca) VALUES (?, ?, ?, ?, ?)',
        (
            correo,
            salt,
            hashed_pw,
            base64.b64encode(clave_publica_con_firma).decode('utf-8'),
            base64.b64encode(clave_publica_firmada_ca).decode('utf-8'),
        )
    )

    conn.commit()
    conn.close()


# Función para verificar el usuario y contraseña
def verificar_usuario(correo, password, ca_certificate):
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()

    # Recuperar los datos del usuario
    cursor.execute(
        'SELECT salt, hashed_pw, clave_publica, clave_publica_ca FROM usuarios WHERE correo = ?',
        (correo,)
    )
    result = cursor.fetchone()
    conn.close()

    if result:
        salt, stored_hashed_pw, clave_publica_encoded, clave_publica_ca_encoded = result
        clave_publica_con_firma = base64.b64decode(clave_publica_encoded)
        clave_publica_firmada_ca = base64.b64decode(clave_publica_ca_encoded)

        # Separar la clave pública y la firma
        clave_publica_pem, firma = clave_publica_con_firma.split(b"\nFIRMA\n")

        # Verificar que la clave pública es válida y firmada por la CA
        if not verificar_clave_publica_con_ca(ca_certificate, clave_publica_firmada_ca):
            print("Advertencia: La clave pública no es válida o no está firmada por la CA.")
            return False
        print("CERTIFICADO Y FIRMA VÁLIDOS")
        print("-------------------------------------------------------")
        # Verificar la firma de los datos del usuario
        datos_a_firmar = f"{correo}{stored_hashed_pw}".encode('utf-8')
        if not verificar_firma(clave_publica_pem, datos_a_firmar, firma):
            print("Advertencia: La firma de los datos del usuario no es válida.")
            return False

        # Verificar la contraseña
        hashed_pw = hash_password_salt(password, salt)
        if stored_hashed_pw == hashed_pw:
            print("La contraseña ingresada coincide con la almacenada.")
            return True

    print("La contraseña ingresada no coincide con la almacenada")
    return False

# Función para insertar una transacción
def insertar_transaccion(usuario_id, criptomoneda, cantidad, valor):
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()
    cursor.execute('SELECT clave_publica FROM usuarios WHERE id = ?', (usuario_id,))
    clave_publica_row = cursor.fetchone()
    cursor.execute('SELECT correo FROM usuarios WHERE id = ?', (usuario_id,))
    correo = cursor.fetchone()
    correo_limpio = ''.join(char for char in correo if char not in [',', '(', ')', ' ']) #Quita parentesis y comas
    

    if clave_publica_row:
            clave_publica_pem = base64.b64decode(clave_publica_row[0])
            
            # Cifrar la información de la transacción
            datos = f'{criptomoneda},{cantidad},{valor}'.encode('utf-8')
            datos_cifrados = cifrar_con_clave_publica(clave_publica_pem, datos)

            # Creamos firma para los datos originales
            ruta_clave_privada = f"./{correo_limpio}_privada.pem"
            firma = firmar_datos(open(ruta_clave_privada, 'rb').read(), datos)

            # Concatenar firma con los datos cifrados
            datos_cifrados_con_firma = datos_cifrados + b"\nFIRMA\n" + firma

            # Crear MAC de la transacción cifrada
            mac = crear_mac_chacha20poly1305(LLAVE_MAC, NONCE, datos_cifrados)
    
            cursor.execute('INSERT INTO transacciones (usuario_id, datos_cifrados, mac) VALUES (?, ?, ?)',
                       (usuario_id, base64.b64encode(datos_cifrados_con_firma).decode('utf-8'), base64.b64encode(mac).decode('utf-8')))
            conn.commit()
    
    conn.close()

# Función para obtener transacciones de un usuario
def obtener_transacciones(usuario_id):
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()
    cursor.execute('SELECT datos_cifrados, mac FROM transacciones WHERE usuario_id = ?', (usuario_id,))
    transacciones_cifradas = cursor.fetchall()
    cursor.execute('SELECT correo FROM usuarios WHERE id = ?', (usuario_id,))
    correo = cursor.fetchone()
    correo_limpio = ''.join(char for char in correo if char not in [',', '(', ')', ' ']) #Quita parentesis y comas
    cursor.execute('SELECT clave_publica FROM usuarios WHERE id = ?', (usuario_id,))
    clave_publica_encoded = cursor.fetchone()
    
    
    ruta_clave_privada = f"{correo_limpio}_privada.pem"
    # Decodificar la clave pública
    clave_publica_pem = base64.b64decode(clave_publica_encoded[0])

    transacciones_descifradas = []
    for transaccion in transacciones_cifradas:
        try:
            datos_cifrados_base64, mac_base64 = transaccion
            print("TRANSACCION A DESCRIFAR")
            print(transaccion)

            datos_cifrados_con_firma = base64.b64decode(datos_cifrados_base64)

            # Decodificar el MAC desde base64
            mac = base64.b64decode(mac_base64)

            # Separar firma y datos cifrados
            datos_cifrados, firma = datos_cifrados_con_firma.split(b"\nFIRMA\n")

            # Verificar la firma
            datos_originales = descifrar_con_clave_privada(f"./{correo_limpio}_privada.pem", datos_cifrados)
            if not verificar_firma(clave_publica_pem, datos_originales, firma):
                print("Advertencia: La firma de esta transacción no es válida.")
                continue

            # Verificar el MAC antes de descifrar
            if verificar_mac_chacha20poly1305(LLAVE_MAC, NONCE, datos_cifrados, mac):
                # Descifro cada transacción usando la clave privada
                datos_descifrados = descifrar_con_clave_privada(ruta_clave_privada, datos_cifrados)
        
                # Convierto los datos descifrados en una lista de criptomoneda, cantidad, valor si hay datos.
                if(datos_descifrados is not None):
                    valores = datos_descifrados.decode('utf-8').split(',')
                    #Compruebo que solo sean los 3 valores que necesito
                    if len(valores) == 3:
                        criptomoneda, cantidad, valor = valores
                        transacciones_descifradas.append((criptomoneda, float(cantidad), float(valor)))
                else:
                    return None
        except ValueError:
            print("Error: La fila de transacción no contiene los valores esperados (datos_cifrados y mac).")
    conn.close()
    return transacciones_descifradas
def es_contrasena_robusta(password):
    if (len(password) < 8 or
            not any(char.isupper() for char in password) or
            not any(char.islower() for char in password) or
            not any(char.isdigit() for char in password) or
            not any(char in "!@#$%^&*()_+[]{}|;:,.<>?/~`" for char in password)): #contener al menos un carácter especial
        return False
    return True

crear_base_datos()
print("¡Base de Datos Creada!")