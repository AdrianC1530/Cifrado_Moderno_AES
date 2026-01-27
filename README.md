# 🔐 Suite de Cifrado Moderno: AES Explorer
Una implementación didáctica y arquitectónica del estándar de cifrado avanzado (AES-128).

Este proyecto es una demostración de ingeniería de software aplicada a la criptografía moderna. Diseñado bajo una Arquitectura de 3 Capas estricta, separa la lógica matemática compleja de la interfaz de usuario, garantizando un código limpio, modular y escalable, ideal para propósitos educativos y de demostración.

## 🌟 Características Destacadas

### 🏛️ Arquitectura Robusta
Diseño "End-to-End" que respeta el patrón Separation of Concerns:
- **Backend Puro:** Lógica matemática de AES-128 (SubBytes, ShiftRows, MixColumns, AddRoundKey) implementada desde cero.
- **Middleware Inteligente:** Capa de validación y manejo de Padding PKCS#7 para asegurar la integridad de los bloques.
- **Frontend Desacoplado:** Interfaz gráfica en Tkinter que visualiza la "Matriz de Estado" y permite la interacción del usuario.

### 🧮 Matemática Computacional
Implementación detallada de operaciones sobre campos finitos (Galois Fields) y operaciones a nivel de bit, fundamentales para la seguridad de AES.

### 🎨 Interfaz Intuitiva
Una GUI construida con Tkinter que permite:
- Cargar texto o archivos.
- Visualizar las claves en Hex/Base64.
- Ver el estado de la matriz de cifrado paso a paso (simulado/didáctico).

## 🛠️ Stack Tecnológico
Este proyecto ha sido construido utilizando estándares de desarrollo profesional:
- **Lenguaje:** 🐍 Python 3.x
- **GUI:** 🖥️ Tkinter (Biblioteca estándar de Python)
- **Arquitectura:** 🏗️ 3-Tier Architecture (Backend, Middleware, Frontend)
- **Control de Versiones:** 🐙 Git

## 🚀 Instalación y Uso

### Prerrequisitos
- Python 3.x instalado en tu sistema.

### Despliegue Rápido
1. Clonar el repositorio:
   ```bash
   git clone https://github.com/AdrianC1530/Cifrado_Moderno_AES.git
   cd Cifrado_Moderno_AES
   ```

2. Ejecutar la aplicación:
   Simplemente corre el archivo principal desde la raíz del proyecto:
   ```bash
   python main.py
   ```

## 📄 Estructura del Proyecto
```
Cifrado_Moderno_AES/
├── 📂 src/
│   ├── 📂 backend/     # 🧠 Lógica pura del cifrado (AES-128)
│   ├── 📂 middleware/  # 🛡️ Padding PKCS#7 y validaciones
│   └── 📂 frontend/    # 🎨 Interfaz Gráfica (GUI)
├── 📄 main.py          # 🏁 Punto de entrada
└── 📄 README.md        # 📖 Documentación
```

## 👤 Autor
Hecho con ❤️ y ☕ por Adrian Carrillo.
