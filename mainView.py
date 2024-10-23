import customtkinter as ctk
from tkinter import messagebox
import os
import json
from json_pathh import data_file
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Configuracion de apariencia general
ctk.set_appearance_mode("dark")  # Modo oscuro
ctk.set_default_color_theme("blue")  # Tema azul

# Ventana principal (para login, registro, portafolio, etc.)
main_window = ctk.CTk()
main_window.title("CryptoMartin")
main_window.geometry("1000x700")
main_window.resizable(True, True)

# Variable para mantener la pantalla actual
current_frame = None

# Inicializar la variable global para contar el número de transacciones
fila_actual = 1

# Funcion para cambiar de frame
def cambiar_frame(nuevo_frame):
    global current_frame
    if current_frame:
        current_frame.destroy()  # Elimina el frame actual antes de cargar el nuevo
    current_frame = nuevo_frame
    current_frame.pack(expand=True, fill="both")  # Expande el nuevo frame para ocupar todo el espacio

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

# Pantalla de Login
def login_screen():
    frame_login = ctk.CTkFrame(main_window)
    
    # Establecer el grid con columnas centradas
    frame_login.grid_columnconfigure(0, weight=1)
    frame_login.grid_columnconfigure(1, weight=1)

    ctk.CTkLabel(frame_login, text="Usuario", font=("Helvetica", 20)).grid(row=0, column=0, padx=10, pady=20, sticky="e")
    username_entry = ctk.CTkEntry(frame_login, width=300, font=("Helvetica", 18))
    username_entry.grid(row=0, column=1, padx=10, pady=20, sticky="w")

    ctk.CTkLabel(frame_login, text="Contraseña", font=("Helvetica", 20)).grid(row=1, column=0, padx=10, pady=20, sticky="e")
    password_entry = ctk.CTkEntry(frame_login, show="*", width=300, font=("Helvetica", 18))
    password_entry.grid(row=1, column=1, padx=10, pady=20, sticky="w")

    def acceso():
        username = username_entry.get()
        password = password_entry.get()
        try:
            verify_hash(username, password)
            messagebox.showinfo("Login", "Acceso exitoso!")
            portfolio_screen(username, password)
        except Exception as e:
            messagebox.showerror("Login Fallido", str(e))

    def registro():
        registro_screen()  # Cambia a la pantalla de registro

    # Botones de Acceder y Registrarse con estilo moderno
    ctk.CTkButton(frame_login, text="Acceder", command=acceso, width=200, height=50, font=("Helvetica", 18)).grid(row=2, column=0, padx=10, pady=20, sticky="e")
    ctk.CTkButton(frame_login, text="Registrarse", command=registro, width=200, height=50, font=("Helvetica", 18)).grid(row=2, column=1, padx=10, pady=20, sticky="w")

    cambiar_frame(frame_login)

# Pantalla de Registro
def registro_screen():
    frame_registro = ctk.CTkFrame(main_window)
    
    # Establecer el grid con columnas centradas
    frame_registro.grid_columnconfigure(0, weight=1)
    frame_registro.grid_columnconfigure(1, weight=1)

    ctk.CTkLabel(frame_registro, text="Correo", font=("Helvetica", 16)).grid(row=0, column=0, padx=10, pady=10, sticky="e")
    correo_entry = ctk.CTkEntry(frame_registro, width=250, font=("Helvetica", 16))
    correo_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

    ctk.CTkLabel(frame_registro, text="Contraseña", font=("Helvetica", 16)).grid(row=1, column=0, padx=10, pady=10, sticky="e")
    password_reg_entry = ctk.CTkEntry(frame_registro, show="*", width=250, font=("Helvetica", 16))
    password_reg_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

    def registrar():
        correo = correo_entry.get()
        password_reg = password_reg_entry.get()
        if correo and password_reg:
            salt, hashed_pw = hash(password_reg)
            investments = {}  # No hay inversiones al momento del registro
            insert_data(correo, salt, hashed_pw, investments, None)
            messagebox.showinfo("Registro", "Registrado con éxito!")
            login_screen()
        else:
            messagebox.showwarning("Error", "Debe completar todos los campos.")

    # Botón para registrar
    ctk.CTkButton(frame_registro, text="Registrar", command=registrar, width=100).grid(row=2, columnspan=2, pady=20)
    
    # Botón para volver al login
    ctk.CTkButton(frame_registro, text="Volver", command=login_screen, width=100).grid(row=3, columnspan=2, pady=10)  

    cambiar_frame(frame_registro)

# Pantalla del Portafolio de Criptomonedas
def portfolio_screen(username, password):
    frame_portfolio = ctk.CTkFrame(main_window)

    inversiones = {}

    # Etiquetas y lista de inversiones con columnas
    ctk.CTkLabel(frame_portfolio, text="Criptomoneda", font=("Helvetica", 18)).grid(row=0, column=0, padx=20, pady=20)
    ctk.CTkLabel(frame_portfolio, text="Cantidad", font=("Helvetica", 18)).grid(row=0, column=1, padx=20, pady=20)
    ctk.CTkLabel(frame_portfolio, text="Valor en USD", font=("Helvetica", 18)).grid(row=0, column=2, padx=20, pady=20)

    inversiones_frame = ctk.CTkFrame(frame_portfolio, width=800, height=400)
    inversiones_frame.grid(row=1, columnspan=3, padx=10, pady=10)

    try:
        with open(data_file, "r", encoding="utf-8", newline="") as df:
            temp = json.load(df)
        for key in temp:
            if key["Nombre"] == username:
                inversiones = key["Inversiones"]
                break
    except FileNotFoundError:
        inversiones = {}

    # Formulario para agregar nuevas transacciones en la misma ventana
    ctk.CTkLabel(frame_portfolio, text="Agregar Nueva Transacción", font=("Helvetica", 20)).grid(row=2, columnspan=3, padx=10, pady=20)

    ctk.CTkLabel(frame_portfolio, text="Criptomoneda", font=("Helvetica", 16)).grid(row=3, column=0, padx=10, pady=10, sticky="e")
    cripto_entry = ctk.CTkEntry(frame_portfolio, width=300, font=("Helvetica", 16))
    cripto_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

    ctk.CTkLabel(frame_portfolio, text="Cantidad", font=("Helvetica", 16)).grid(row=4, column=0, padx=10, pady=10, sticky="e")
    cantidad_entry = ctk.CTkEntry(frame_portfolio, width=300, font=("Helvetica", 16))
    cantidad_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

    ctk.CTkLabel(frame_portfolio, text="Valor en USD", font=("Helvetica", 16)).grid(row=5, column=0, padx=10, pady=10, sticky="e")
    valor_entry = ctk.CTkEntry(frame_portfolio, width=300, font=("Helvetica", 16))
    valor_entry.grid(row=5, column=1, padx=10, pady=10, sticky="w")

    

    def agregar_transaccion():
        global fila_actual
        cripto = cripto_entry.get()
        cantidad = float(cantidad_entry.get())
        valor = float(valor_entry.get())

        if cripto and cantidad > 0 and valor > 0:
            inversiones[cripto] = (cantidad, valor)
            transaccion = insert_cripto(username, cripto, cantidad, valor, password)
            cripto, cantidad, val = transaccion.split(',')
            valor = float(val)
                
            ctk.CTkLabel(inversiones_frame, text=cripto, font=("Helvetica", 14)).grid(row=fila_actual, column=0, padx=20, pady=10)
            ctk.CTkLabel(inversiones_frame, text=f"{cantidad}", font=("Helvetica", 14)).grid(row=fila_actual, column=1, padx=20, pady=10)
            ctk.CTkLabel(inversiones_frame, text=f"${valor:.2f}", font=("Helvetica", 14)).grid(row=fila_actual, column=2, padx=20, pady=10)

            # Incrementar la fila para la próxima transacción
            fila_actual += 1

            # Limpiar entradas
            cripto_entry.delete(0, 'end')
            cantidad_entry.delete(0, 'end')
            valor_entry.delete(0, 'end')
        else:
            messagebox.showwarning("Error", "Todos los campos deben ser válidos.")

    # Botón para agregar nueva transacción
    ctk.CTkButton(frame_portfolio, text="Agregar Transacción", command=agregar_transaccion, width=300, height=40, font=("Helvetica", 16)).grid(row=6, columnspan=2, pady=20)

    ctk.CTkButton(frame_portfolio, text="Cerrar sesión", command=login_screen, width=150, height=40, font=("Helvetica", 16)).grid(row=7, columnspan=3, pady=20)

    cambiar_frame(frame_portfolio)
    frame_portfolio.pack(expand=True, fill="both")

# Pantalla principal
login_screen()
main_window.mainloop()
