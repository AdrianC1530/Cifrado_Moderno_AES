import tkinter as tk
from src.frontend.gui import AESApp

def main():
    root = tk.Tk()
    # Set icon if available, otherwise skip
    # root.iconbitmap('icon.ico') 
    
    app = AESApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
