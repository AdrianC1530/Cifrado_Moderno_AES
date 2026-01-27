import tkinter as tk
from tkinter import ttk, messagebox
import binascii

# Importar backend y middleware
try:
    from src.backend.aes import AESBackend
    from src.middleware.padding import PKCS7Padding, Validator
except ImportError:
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from src.backend.aes import AESBackend
    from src.middleware.padding import PKCS7Padding, Validator

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Explorador AES-128 | Edición Moderna")
        self.root.geometry("1000x750")
        
        # --- Paleta de Tema Oscuro Moderno ---
        self.colors = {
            "bg_main": "#1E1E1E",       # Gris Oscuro (Estilo VS Code)
            "bg_panel": "#252526",      # Gris ligeramente más claro
            "fg_text": "#D4D4D4",       # Texto gris claro
            "accent": "#007ACC",        # Acento Azul
            "accent_hover": "#005f9e",
            "matrix_bg": "#333333",
            "matrix_fg": "#9CDCFE",     # Azul claro para hex
            "success": "#4EC9B0",       # Verdoso
            "warning": "#CE9178"        # Naranja/Rojizo
        }

        self.root.configure(bg=self.colors["bg_main"])
        
        self.backend = AESBackend()
        self.padder = PKCS7Padding()
        self.validator = Validator()

        self.current_state_history = []
        self.current_step_index = 0
        self.is_decrypting = False

        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam') # 'clam' permite más personalización que 'vista' o 'default'

        # Marco/Etiqueta General
        style.configure("TFrame", background=self.colors["bg_main"])
        style.configure("TLabel", background=self.colors["bg_main"], foreground=self.colors["fg_text"], font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground=self.colors["accent"])
        style.configure("SubHeader.TLabel", font=("Segoe UI", 12, "bold"), foreground=self.colors["fg_text"])
        
        # Paneles
        style.configure("Panel.TFrame", background=self.colors["bg_panel"], relief="flat")
        style.configure("Panel.TLabel", background=self.colors["bg_panel"], foreground=self.colors["fg_text"])

        # Botones (Planos Modernos)
        style.configure("Accent.TButton", 
                        font=("Segoe UI", 10, "bold"), 
                        background=self.colors["accent"], 
                        foreground="white", 
                        borderwidth=0, 
                        focuscolor=self.colors["accent"])
        style.map("Accent.TButton", 
                  background=[('active', self.colors["accent_hover"])])

        style.configure("Nav.TButton", 
                        font=("Segoe UI", 10), 
                        background="#3C3C3C", 
                        foreground="white", 
                        borderwidth=0)
        style.map("Nav.TButton", 
                  background=[('active', "#505050")])

        # Entrada de texto
        style.configure("Modern.TEntry", 
                        fieldbackground="#3C3C3C", 
                        foreground="white", 
                        insertcolor="white", 
                        borderwidth=0,
                        padding=5)

    def setup_ui(self):
        # --- Encabezado ---
        header_frame = ttk.Frame(self.root, padding="20 20 20 10")
        header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="EXPLORADOR AES-128", style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(header_frame, text="Herramienta de Visualización Didáctica", style="TLabel").pack(side=tk.LEFT, padx=10, pady=(8,0))

        # --- Diseño Principal ---
        main_container = ttk.Frame(self.root, padding="20")
        main_container.pack(fill=tk.BOTH, expand=True)

        # Columna Izquierda: Controles (40%)
        left_col = ttk.Frame(main_container)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 20))

        # Columna Derecha: Visualización (60%)
        right_col = ttk.Frame(main_container)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # --- Sección de Entrada (Izquierda) ---
        input_panel = ttk.Frame(left_col) # Contenedor transparente
        input_panel.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(input_panel, text="DATOS DE ENTRADA (UTF-8)", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(0, 5))
        
        self.input_text = tk.Text(input_panel, height=4, bg="#3C3C3C", fg="white", 
                                  font=("Consolas", 10), relief="flat", insertbackground="white")
        self.input_text.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(input_panel, text="CLAVE SECRETA (16 CARACTERES)", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(0, 5))
        self.key_entry = ttk.Entry(input_panel, style="Modern.TEntry", font=("Consolas", 10))
        self.key_entry.pack(fill=tk.X, pady=(0, 15), ipady=3)
        self.key_entry.insert(0, "Thats my Kung Fu")

        # Botones de Acción
        btn_frame = ttk.Frame(input_panel)
        btn_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.btn_encrypt = ttk.Button(btn_frame, text="🔒 CIFRAR", style="Accent.TButton", command=self.encrypt)
        self.btn_encrypt.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.btn_decrypt = ttk.Button(btn_frame, text="🔓 DESCIFRAR", style="Nav.TButton", command=self.decrypt)
        self.btn_decrypt.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        # Sección de Salida
        ttk.Label(input_panel, text="SALIDA (HEX)", style="SubHeader.TLabel").pack(anchor=tk.W, pady=(0, 5))
        self.output_text = tk.Text(input_panel, height=4, bg="#2D2D2D", fg=self.colors["success"], 
                                   font=("Consolas", 10), relief="flat", state="disabled")
        self.output_text.pack(fill=tk.X)

        # --- Sección de Visualización (Derecha) ---
        vis_panel = ttk.Frame(right_col, style="Panel.TFrame", padding="20") # Fondo más oscuro
        vis_panel.pack(fill=tk.BOTH, expand=True)

        ttk.Label(vis_panel, text="MATRIZ DE ESTADO", style="Header.TLabel", background=self.colors["bg_panel"]).pack(pady=(0, 20))

        # La Cuadrícula (Grid)
        matrix_frame = ttk.Frame(vis_panel, style="Panel.TFrame")
        matrix_frame.pack(expand=True)
        
        self.matrix_cells = []
        for r in range(4):
            row_cells = []
            for c in range(4):
                # Usando un Frame para crear efecto de borde
                cell_border = tk.Frame(matrix_frame, bg="#505050", padx=1, pady=1)
                cell_border.grid(row=r, column=c, padx=5, pady=5)
                
                cell = tk.Label(cell_border, text="00", font=("Consolas", 18, "bold"), 
                                 bg=self.colors["matrix_bg"], fg=self.colors["matrix_fg"], 
                                 width=4, height=2)
                cell.pack()
                row_cells.append(cell)
            self.matrix_cells.append(row_cells)

        # Controles de Pasos
        control_frame = ttk.Frame(vis_panel, style="Panel.TFrame")
        control_frame.pack(fill=tk.X, pady=20)

        self.step_label = ttk.Label(control_frame, text="Listo para Iniciar", 
                                    font=("Segoe UI", 12), foreground="#888", background=self.colors["bg_panel"])
        self.step_label.pack(pady=(0, 10))

        nav_btns = ttk.Frame(control_frame, style="Panel.TFrame")
        nav_btns.pack()
        
        ttk.Button(nav_btns, text="⏮ ANTERIOR", style="Nav.TButton", command=self.prev_step).pack(side=tk.LEFT, padx=5)
        ttk.Button(nav_btns, text="SIGUIENTE ⏭", style="Nav.TButton", command=self.next_step).pack(side=tk.LEFT, padx=5)

    def update_matrix(self, state):
        for c in range(4):
            for r in range(4):
                val = state[c][r]
                self.matrix_cells[r][c].config(text=f"{val:02X}")

    def encrypt(self):
        try:
            plaintext = self.input_text.get("1.0", tk.END).strip()
            key_str = self.key_entry.get()

            if not plaintext:
                messagebox.showwarning("Error de Entrada", "Por favor ingrese algún texto.")
                return

            key_bytes = self.validator.validate_key(key_str)
            data_bytes = plaintext.encode('utf-8')
            padded_data = self.padder.pad(data_bytes)
            
            ciphertext = b""
            first_block_trace = None
            
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                if i == 0:
                    encrypted_block, trace = self.backend.encrypt_block(block, key_bytes, trace=True)
                    first_block_trace = trace
                else:
                    encrypted_block = self.backend.encrypt_block(block, key_bytes, trace=False)
                ciphertext += encrypted_block

            hex_output = binascii.hexlify(ciphertext).decode('utf-8').upper()
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", hex_output)
            self.output_text.config(state="disabled")

            self.current_state_history = first_block_trace
            self.current_step_index = 0
            self.is_decrypting = False
            self.show_step()
            self.step_label.config(foreground=self.colors["accent"])

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        try:
            hex_input = self.input_text.get("1.0", tk.END).strip()
            key_str = self.key_entry.get()

            if not hex_input:
                messagebox.showwarning("Error de Entrada", "Por favor ingrese el texto cifrado en Hex.")
                return

            key_bytes = self.validator.validate_key(key_str)
            
            try:
                ciphertext = binascii.unhexlify(hex_input)
            except binascii.Error:
                messagebox.showerror("Error de Formato", "La entrada debe ser Hexadecimal válido.")
                return

            decrypted_padded = b""
            first_block_trace = None
            
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i+16]
                if i == 0:
                    decrypted_block, trace = self.backend.decrypt_block(block, key_bytes, trace=True)
                    first_block_trace = trace
                else:
                    decrypted_block = self.backend.decrypt_block(block, key_bytes, trace=False)
                decrypted_padded += decrypted_block

            try:
                plaintext_bytes = self.padder.unpad(decrypted_padded)
                plaintext = plaintext_bytes.decode('utf-8')
            except Exception as e:
                plaintext = f"[Error]: {e}"

            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", plaintext)
            self.output_text.config(state="disabled")
            
            self.current_state_history = first_block_trace
            self.current_step_index = 0
            self.is_decrypting = True
            self.show_step()
            self.step_label.config(foreground=self.colors["success"])

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_step(self):
        if not self.current_state_history:
            return
            
        state = self.current_state_history[self.current_step_index]
        self.update_matrix(state)
        
        round_name = "Desconocido"
        
        if not self.is_decrypting:
            # Etiquetas para Cifrado
            if self.current_step_index == 0:
                round_name = "Estado Inicial (Texto Plano)"
            elif self.current_step_index == 1:
                round_name = "Ronda 0: AddRoundKey"
            elif 2 <= self.current_step_index <= 10:
                round_name = f"Ronda {self.current_step_index - 1}: Ciclo Completo"
            elif self.current_step_index == 11:
                round_name = "Ronda Final (Sin MixColumns)"
        else:
            # Etiquetas para Descifrado
            if self.current_step_index == 0:
                round_name = "Estado Inicial (Cifrado)"
            elif self.current_step_index == 1:
                round_name = "Ronda Inv Inicial (AddKey10+InvShift+InvSub)"
            elif 2 <= self.current_step_index <= 10:
                round_name = f"Ronda Inv {11 - self.current_step_index}: Ciclo Completo"
            elif self.current_step_index == 11:
                round_name = "Ronda Inv Final (AddKey0 -> Texto Plano)"
            
        self.step_label.config(text=f"Paso {self.current_step_index}/11: {round_name}")

    def next_step(self):
        if self.current_step_index < len(self.current_state_history) - 1:
            self.current_step_index += 1
            self.show_step()

    def prev_step(self):
        if self.current_step_index > 0:
            self.current_step_index -= 1
            self.show_step()

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
