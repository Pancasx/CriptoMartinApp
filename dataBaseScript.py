import sqlite3
import os
import hashlib
import os
import base64

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
                hashed_pw TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE transacciones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                criptomoneda TEXT,
                cantidad REAL,
                valor REAL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        conn.commit()
        conn.close()

# Función para hashear la contraseña
def hash_password(password):
    salt = os.urandom(16)
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt).decode('utf-8'), base64.b64encode(hashed_pw).decode('utf-8')

# Función para insertar un nuevo usuario
def insertar_usuario(correo, password):
    salt, hashed_pw = hash_password(password)
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()
    cursor.execute('INSERT INTO usuarios (correo, salt, hashed_pw) VALUES (?, ?, ?)', (correo, salt, hashed_pw))
    conn.commit()
    conn.close()

# Función para verificar el usuario y contraseña
def verificar_usuario(correo, password):
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()
    cursor.execute('SELECT salt, hashed_pw FROM usuarios WHERE correo = ?', (correo,))
    result = cursor.fetchone()
    conn.close()

    if result:
        salt, stored_hashed_pw = result
        salt = base64.b64decode(salt.encode('utf-8'))
        hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        if stored_hashed_pw == base64.b64encode(hashed_pw).decode('utf-8'):
            return True
    return False

# Función para insertar una transacción
def insertar_transaccion(usuario_id, criptomoneda, cantidad, valor):
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()
    cursor.execute('INSERT INTO transacciones (usuario_id, criptomoneda, cantidad, valor) VALUES (?, ?, ?, ?)', 
                   (usuario_id, criptomoneda, cantidad, valor))
    conn.commit()
    conn.close()

# Función para obtener transacciones de un usuario
def obtener_transacciones(usuario_id):
    conn = sqlite3.connect("cryptomartin.db")
    cursor = conn.cursor()
    cursor.execute('SELECT criptomoneda, cantidad, valor FROM transacciones WHERE usuario_id = ?', (usuario_id,))
    transacciones = cursor.fetchall()
    conn.close()
    return transacciones

def es_contrasena_robusta(password):
    if (len(password) < 8 or
            not any(char.isupper() for char in password) or
            not any(char.islower() for char in password) or
            not any(char.isdigit() for char in password) or
            not any(char in "!@#$%^&*()_+[]{}|;:,.<>?/~`" for char in password)): #contener al menos un carácter especial
        return False
    return True

crear_base_datos()
print("Creada")