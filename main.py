import tkinter as tk
from src.frontend.gui import AESApp

def main():
    root = tk.Tk()
    # Establecer icono si está disponible, de lo contrario omitir
    # root.iconbitmap('icon.ico') 
    
    app = AESApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
