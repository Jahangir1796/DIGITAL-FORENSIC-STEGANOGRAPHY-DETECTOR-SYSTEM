class MultiLayerEncryption:
    def __init__(self):
        self.layers = []
    
    def add_layer(self, algorithm, key):
        """Add encryption layer."""
        self.layers.append({
            'algorithm': algorithm,
            'key': key,
            'strength': self.calculate_strength(algorithm)
        })
    
    def encrypt(self, data):
        """Apply multiple encryption layers."""
        encrypted = data
        for layer in self.layers:
            if layer['algorithm'] == 'AES-256':
                encrypted = self.aes_encrypt(encrypted, layer['key'])
            elif layer['algorithm'] == 'ChaCha20':
                encrypted = self.chacha_encrypt(encrypted, layer['key'])
            # Add more algorithms
        
        return encrypted
    
    def calculate_strength(self, algorithm):
        """Calculate encryption strength."""
        strengths = {
            'AES-256': 100,
            'ChaCha20': 95,
            'Blowfish': 85,
            'DES': 40
        }
        return strengths.get(algorithm, 0)