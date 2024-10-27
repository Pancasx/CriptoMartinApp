import sqlite3
import customtkinter as ctk
import re
from tkinter import messagebox
from dataBaseScript import crear_base_datos, insertar_usuario, verificar_usuario, insertar_transaccion, obtener_transacciones, es_contrasena_robusta

class CryptoMartinApp:
    def __init__(self):
        # Configuración de la ventana principal
        self.main_window = ctk.CTk()
        self.main_window.title("CryptoMartin")
        self.main_window.geometry("1000x700")
        self.main_window.resizable(True, True)
        self.username = ""
        
        self.current_frame = None
        
        # Creo base de datos y tabla (si ya existe no se crea otra vez)
        crear_base_datos()

        # Inicia la pantalla de login
        self.login_screen()

    def cambiar_frame(self, nuevo_frame):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = nuevo_frame
        self.current_frame.pack(expand=True, fill="both")

    def login_screen(self):
        frame_login = ctk.CTkFrame(self.main_window)

        frame_login.grid_columnconfigure(0, weight=1)
        frame_login.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(frame_login, text="Usuario", font=("Helvetica", 20)).grid(row=0, column=0, padx=10, pady=20, sticky="e")
        username_entry = ctk.CTkEntry(frame_login, width=300, font=("Helvetica", 18))
        username_entry.grid(row=0, column=1, padx=10, pady=20, sticky="w")

        ctk.CTkLabel(frame_login, text="Contraseña", font=("Helvetica", 20)).grid(row=1, column=0, padx=10, pady=20, sticky="e")
        password_entry = ctk.CTkEntry(frame_login, show="*", width=300, font=("Helvetica", 18))
        password_entry.grid(row=1, column=1, padx=10, pady=20, sticky="w")

        def acceso():
            self.username = username_entry.get()
            password = password_entry.get()
            #Función de dataBase para verificar la existencia del usuario/contraseña en la base de datos
            if verificar_usuario(self.username, password): 
                
                messagebox.showinfo("Login", "Acceso exitoso!")
                self.portfolio_screen()
            else:
                messagebox.showerror("Login Fallido", "Usuario o contraseña incorrectos.")

        def registro():
            self.registro_screen()

        ctk.CTkButton(frame_login, text="Acceder", command=acceso, width=200, height=50, font=("Helvetica", 18)).grid(row=2, column=0, padx=10, pady=20, sticky="e")
        ctk.CTkButton(frame_login, text="Registrarse", command=registro, width=200, height=50, font=("Helvetica", 18)).grid(row=2, column=1, padx=10, pady=20, sticky="w")

        self.cambiar_frame(frame_login)

    def registro_screen(self):
        frame_registro = ctk.CTkFrame(self.main_window)

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

            #RegEx para correo
            correo_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

            if correo and password_reg:
                if not re.match(correo_regex, correo):  # Comprobar si el correo es válido
                    messagebox.showerror("Error", "Debe introducir un correo electrónico válido.")
                    return
                if es_contrasena_robusta(password_reg):
                    try:
                        insertar_usuario(correo, password_reg)
                        messagebox.showinfo("Registro", "Registrado con éxito!")
                        self.login_screen()
                    except Exception as e:
                        error_str = str(e)
                        if(error_str.startswith("UNIQUE")):
                            messagebox.showerror("Error", "Usuario ya registrado")
                        else:
                            messagebox.showerror("Error", str(e))
                else:
                    messagebox.showwarning("Error","La contraseña debe contener:\n-Al menos 8 caracteres\n-Al menos una minúscula y una mayúscula\n-Al menos un carácter especial")
            else:
                messagebox.showwarning("Error", "Debe completar todos los campos.")

        ctk.CTkButton(frame_registro, text="Registrar", command=registrar, width=100).grid(row=2, columnspan=2, pady=20)
        ctk.CTkButton(frame_registro, text="Volver", command=self.login_screen, width=100).grid(row=3, columnspan=2, pady=10)

        self.cambiar_frame(frame_registro)

    def portfolio_screen(self):
        frame_portfolio = ctk.CTkFrame(self.main_window)

        ctk.CTkLabel(frame_portfolio, text="Criptomoneda", font=("Helvetica", 18)).grid(row=0, column=0, padx=20, pady=20)
        ctk.CTkLabel(frame_portfolio, text="Cantidad", font=("Helvetica", 18)).grid(row=0, column=1, padx=20, pady=20)
        ctk.CTkLabel(frame_portfolio, text="Valor en USD", font=("Helvetica", 18)).grid(row=0, column=2, padx=20, pady=20)

        # Marco de inversiones (tabla)
        self.inversiones_frame = ctk.CTkFrame(frame_portfolio, width=800, height=400)
        self.inversiones_frame.grid(row=1, columnspan=3, padx=10, pady=10)

        # Obtener ID del usuario
        conn = sqlite3.connect("cryptomartin.db")
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM usuarios WHERE correo = ?', (self.username,))
        usuario_id = cursor.fetchone()[0]
        conn.close()

        # Cargar transacciones
        self.cargar_transacciones(usuario_id)

        # Entradas para nuevas transacciones
        ctk.CTkLabel(frame_portfolio, text="Nueva Transacción", font=("Helvetica", 20)).grid(row=2, columnspan=3, padx=10, pady=10)
        
        criptomoneda_entry = ctk.CTkEntry(frame_portfolio, width=250)
        criptomoneda_entry.grid(row=3, column=0, padx=20, pady=10)

        cantidad_entry = ctk.CTkEntry(frame_portfolio, width=250)
        cantidad_entry.grid(row=3, column=1, padx=20, pady=10)

        valor_entry = ctk.CTkEntry(frame_portfolio, width=250)
        valor_entry.grid(row=3, column=2, padx=20, pady=10)

        def guardar_transaccion():
            criptomoneda = criptomoneda_entry.get()
            cantidad = float(cantidad_entry.get())
            valor = float(valor_entry.get())

            if criptomoneda and cantidad > 0 and valor > 0:
                conn = sqlite3.connect("cryptomartin.db")
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM usuarios WHERE correo = ?', (self.username,))
                usuario_id = cursor.fetchone()[0]
                insertar_transaccion(usuario_id, criptomoneda, cantidad, valor)
                conn.close()
                self.cargar_transacciones(usuario_id)
                messagebox.showinfo("Transacción", "Transacción guardada con éxito!")
            else:
                messagebox.showwarning("Error", "Los campos de transacción deben ser válidos.")

        ctk.CTkButton(frame_portfolio, text="Guardar Transacción", command=guardar_transaccion).grid(row=4, columnspan=3, pady=20)

        ctk.CTkButton(frame_portfolio, text="Cerrar Sesión", command=self.cerrar_sesion).grid(row=5, columnspan=3, pady=20)

        self.cambiar_frame(frame_portfolio)

    def cargar_transacciones(self, usuario_id):
        for widget in self.inversiones_frame.winfo_children():
            widget.destroy()

        transacciones = obtener_transacciones(usuario_id)

        if(transacciones is not None):
            for index, (criptomoneda, cantidad, valor) in enumerate(transacciones):
                ctk.CTkLabel(self.inversiones_frame, text=criptomoneda).grid(row=index, column=0, padx=10, pady=10)
                ctk.CTkLabel(self.inversiones_frame, text=cantidad).grid(row=index, column=1, padx=10, pady=10)
                ctk.CTkLabel(self.inversiones_frame, text=valor).grid(row=index, column=2, padx=10, pady=10)

    def cerrar_sesion(self):
        self.username = ""
        self.login_screen()

if __name__ == "__main__":
    app = CryptoMartinApp()
    app.main_window.mainloop()