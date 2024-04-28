from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(public_key, message):
    return public_key.encrypt(
        message.to_bytes((message.bit_length() + 7) // 8, byteorder='big'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt(private_key, ciphertext):
    return int.from_bytes(private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ), byteorder='big')

# Simulate the process
A_private, A_public = generate_keys()
B_private, B_public = generate_keys()

# Party A encrypts their set
set_A = {1, 2, 3}
encrypted_set_A = [encrypt(B_public, x) for x in set_A]

# Party B encrypts their set and decrypts A's encrypted set to check for intersections
set_B = {3, 4, 5}
encrypted_set_B = {decrypt(B_private, encrypt(B_public, y)): y for y in set_B}
intersection = {encrypted_set_B[decrypt(B_private, x)] for x in encrypted_set_A if decrypt(B_private, x) in encrypted_set_B}

print("Intersection:", intersection)
