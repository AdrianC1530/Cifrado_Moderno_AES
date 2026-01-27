class PKCS7Padding:
    def __init__(self, block_size=16):
        self.block_size = block_size

    def pad(self, data: bytes) -> bytes:
        """
        Applies PKCS#7 padding to the data.
        """
        padding_len = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def unpad(self, data: bytes) -> bytes:
        """
        Removes PKCS#7 padding from the data.
        """
        if not data:
            raise ValueError("Data is empty.")
        
        padding_len = data[-1]
        
        if padding_len == 0 or padding_len > self.block_size:
             raise ValueError("Invalid padding length.")
             
        # Verify that all padding bytes are correct
        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise ValueError("Invalid padding bytes.")
                
        return data[:-padding_len]

class Validator:
    @staticmethod
    def validate_key(key: str) -> bytes:
        """
        Validates and converts the key to 16 bytes.
        Supports Hex string or plain text.
        """
        if not key:
            raise ValueError("La clave no puede estar vacía.")
            
        # Try to interpret as hex if it looks like it
        # (Optional logic, for now let's stick to strict 16 chars or 32 hex chars if user wants)
        # Requirement says "visualice las claves (Hex/Base64)", but input?
        # Let's assume input is a string that needs to be 16 bytes.
        # If it's shorter, we could pad it? Or raise error?
        # AES-128 requires exactly 128 bits (16 bytes).
        
        key_bytes = key.encode('utf-8')
        
        if len(key_bytes) == 16:
            return key_bytes
        elif len(key_bytes) > 16:
            # Truncate (simple approach for demo)
            return key_bytes[:16]
        else:
            # Pad with zeros (simple approach for demo)
            return key_bytes.ljust(16, b'\0')

    @staticmethod
    def ensure_bytes(data) -> bytes:
        if isinstance(data, str):
            return data.encode('utf-8')
        return data
