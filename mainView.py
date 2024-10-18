import customtkinter as ctk
from tkinter import messagebox

# Configuración de apariencia general
ctk.set_appearance_mode("dark")  # Modo oscuro
ctk.set_default_color_theme("blue")  # Tema azul

# Ventana principal (para login, registro, portafolio, etc.)
main_window = ctk.CTk()
main_window.title("CryptoMartin")
main_window.geometry("1000x700")

# Variable para mantener la pantalla actual
current_frame = None

# Función para cambiar de frame
def cambiar_frame(nuevo_frame):
    global current_frame
    if current_frame:
        current_frame.destroy()  # Elimina el frame actual antes de cargar el nuevo
    current_frame = nuevo_frame
    current_frame.pack(expand=True, fill="both")  # Expande el nuevo frame para ocupar todo el espacio

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
        portfolio_screen()

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
            messagebox.showinfo("Registro", "Registrado con éxito!")
            login_screen()  # Vuelve a la pantalla de login después del registro
        else:
            messagebox.showwarning("Error", "Debe completar todos los campos.")

    # Botón para registrar
    ctk.CTkButton(frame_registro, text="Registrar", command=registrar, width=100).grid(row=2, columnspan=2, pady=20)
    
    # Botón para volver al login
    ctk.CTkButton(frame_registro, text="Volver", command=login_screen, width=100).grid(row=3, columnspan=2, pady=10)  

    cambiar_frame(frame_registro)

# Pantalla del Portafolio de Criptomonedas
def portfolio_screen():
    frame_portfolio = ctk.CTkFrame(main_window)

    # Datos iniciales del portafolio
    inversiones = {}

    # Etiquetas y lista de inversiones con columnas
    ctk.CTkLabel(frame_portfolio, text="Criptomoneda", font=("Helvetica", 18)).grid(row=0, column=0, padx=20, pady=20)
    ctk.CTkLabel(frame_portfolio, text="Cantidad", font=("Helvetica", 18)).grid(row=0, column=1, padx=20, pady=20)
    ctk.CTkLabel(frame_portfolio, text="Valor en USD", font=("Helvetica", 18)).grid(row=0, column=2, padx=20, pady=20)

    inversiones_frame = ctk.CTkFrame(frame_portfolio, width=800, height=400)
    inversiones_frame.grid(row=1, columnspan=3, padx=10, pady=10)

    # Filas dinámicas de la lista
    def actualizar_lista():
        for widget in inversiones_frame.winfo_children():
            widget.destroy()

        for idx, (cripto, (cantidad, valor)) in enumerate(inversiones.items()):
            ctk.CTkLabel(inversiones_frame, text=cripto, font=("Helvetica", 14)).grid(row=idx, column=0, padx=20, pady=10)
            ctk.CTkLabel(inversiones_frame, text=f"{cantidad}", font=("Helvetica", 14)).grid(row=idx, column=1, padx=20, pady=10)
            ctk.CTkLabel(inversiones_frame, text=f"${valor:.2f}", font=("Helvetica", 14)).grid(row=idx, column=2, padx=20, pady=10)

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
        cripto = cripto_entry.get()
        cantidad = float(cantidad_entry.get())
        valor = float(valor_entry.get())

        if cripto and cantidad > 0 and valor > 0:
            inversiones[cripto] = (cantidad, valor)
            actualizar_lista()
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

# Pantalla principal
login_screen()
main_window.mainloop()
