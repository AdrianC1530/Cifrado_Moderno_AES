import binascii

class PKCS7Padding:
    def __init__(self, block_size=16):
        self.block_size = block_size

    def pad(self, data: bytes) -> bytes:
        """
        Aplica relleno (padding) PKCS#7 a los datos.
        """
        padding_len = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def unpad(self, data: bytes) -> bytes:
        """
        Elimina el relleno PKCS#7 de los datos.
        """
        if not data:
            raise ValueError("Los datos están vacíos.")
        
        padding_len = data[-1]
        
        if padding_len == 0 or padding_len > self.block_size:
             raise ValueError("Longitud de relleno inválida.")
             
        # Verificar que todos los bytes de relleno sean correctos
        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise ValueError("Bytes de relleno inválidos.")
                
        return data[:-padding_len]

class Validator:
    @staticmethod
    def validate_key(key: str) -> bytes:
        """
        Valida y convierte la clave a 16 bytes.
        Soporta cadena Hex o texto plano.
        """
        if not key:
            raise ValueError("La clave no puede estar vacía.")
            
        key_bytes = key.encode('utf-8')
        
        if len(key_bytes) == 16:
            return key_bytes
        elif len(key_bytes) > 16:
            # Truncar (enfoque simple para demostración)
            return key_bytes[:16]
        else:
            # Rellenar con ceros (enfoque simple para demostración)
            return key_bytes.ljust(16, b'\0')

    @staticmethod
    def ensure_bytes(data) -> bytes:
        """Asegura que los datos sean bytes."""
        if isinstance(data, str):
            return data.encode('utf-8')
        return data

    @staticmethod
    def validate_plaintext(text: str) -> str:
        """Valida que el texto plano no esté vacío."""
        if not text or not text.strip():
            raise ValueError("Por favor ingrese algún texto para cifrar.")
        return text

    @staticmethod
    def validate_ciphertext_hex(hex_str: str) -> bytes:
        """Valida que el texto cifrado no esté vacío y sea hexadecimal válido."""
        if not hex_str or not hex_str.strip():
            raise ValueError("Por favor ingrese el texto cifrado en Hex.")
        
        try:
            return binascii.unhexlify(hex_str.strip())
        except binascii.Error:
            raise ValueError("La entrada debe ser Hexadecimal válido.")

    @staticmethod
    def validate_decrypted_text(data: bytes) -> str:
        """Intenta decodificar los bytes a UTF-8, manejando errores."""
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Error al descifrar: La clave puede ser incorrecta o los datos no son texto válido.")
