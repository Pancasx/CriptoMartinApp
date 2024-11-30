import sqlite3
import os
import hashlib
import base64
from criptography import hash_password, generar_par_de_claves, cifrar_con_clave_publica,descifrar_con_clave_privada, hash_password_salt, crear_mac_chacha20poly1305, verificar_mac_chacha20poly1305, firmar_datos, verificar_firma

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
                clave_publica TEXT
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
def insertar_usuario(correo, password):
    salt, hashed_pw = hash_password(password)

    clave_privada_pem, clave_publica_pem = generar_par_de_claves()  # Generar claves al registrar

    # Crear firma de los datos del usuario
    datos_a_firmar = f"{correo}{hashed_pw}".encode('utf-8')
    firma = firmar_datos(clave_privada_pem, datos_a_firmar)

    # Concatenar la firma con la clave pública
    clave_publica_con_firma = clave_publica_pem + b"\nFIRMA\n" + firma

    # Guardo clave privada en el ordenador del usuario (archivo en la carpeta actual del proyecto)
    ruta_clave_privada = f"./{correo}_privada.pem"  # Correo como nombre de archivo
    with open(ruta_clave_privada, 'wb') as archivo_privado:
        archivo_privado.write(clave_privada_pem)

    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor() #creo un cursos para ejecutar comandos en la DB
    #Se inserta la clave pública en la DB
    cursor.execute('INSERT INTO usuarios (correo, salt, hashed_pw, clave_publica) VALUES (?, ?, ?, ?)', 
                   (correo, salt, hashed_pw, base64.b64encode(clave_publica_con_firma).decode('utf-8')))
    conn.commit()
    conn.close()


# Función para verificar el usuario y contraseña
def verificar_usuario(correo, password):
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor() #creo un cursos para ejecutar comandos en la DB
    cursor.execute('SELECT salt, hashed_pw, clave_publica FROM usuarios WHERE correo = ?', (correo,)) #Consulta a DB
    result = cursor.fetchone() #Devuelve tupla salt, hashed_pw, clave_publica (Recupera la primera fila de resultados y como solo habrá una fila recupera el que necesitamos)
    conn.close()

    if result: #Si el correo si está en la base de datos comprobamos que la contraseña sea correcta
        salt, stored_hashed_pw, clave_publica_encoded = result
        clave_publica_con_firma = base64.b64decode(clave_publica_encoded)

        # Separar la clave pública y la firma
        clave_publica_pem, firma = clave_publica_con_firma.split(b"\nFIRMA\n")

        # Verificar la firma
        datos_a_firmar = f"{correo}{stored_hashed_pw}".encode('utf-8')
        if not verificar_firma(clave_publica_pem, datos_a_firmar, firma):
            print("Advertencia: La firma de este usuario no es válida.")
            return False
        
        hashed_pw = hash_password_salt(password,salt)
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

    if clave_publica_row:
            clave_publica_pem = base64.b64decode(clave_publica_row[0])
            
            # Cifrar la información de la transacción
            datos = f'{criptomoneda},{cantidad},{valor}'.encode('utf-8')
            datos_cifrados = cifrar_con_clave_publica(clave_publica_pem, datos)

            # Crear MAC de la transacción cifrada
            mac = crear_mac_chacha20poly1305(LLAVE_MAC, NONCE, datos_cifrados)
    
            cursor.execute('INSERT INTO transacciones (usuario_id, datos_cifrados, mac) VALUES (?, ?, ?)',
                       (usuario_id, datos_cifrados.decode('utf-8'), base64.b64encode(mac).decode('utf-8')))
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
    conn.close()
    
    ruta_clave_privada = f"{correo_limpio}_privada.pem"

    transacciones_descifradas = []
    for transaccion in transacciones_cifradas:
        try:
            datos_cifrados, mac_base64 = transaccion
            print("TRANSACCION A DESCRIFAR")
            print(transaccion)

            # Decodificar el MAC desde base64
            mac = base64.b64decode(mac_base64)

            # Verificar el MAC antes de descifrar
            if verificar_mac_chacha20poly1305(LLAVE_MAC, NONCE, datos_cifrados.encode('utf-8'), mac):
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