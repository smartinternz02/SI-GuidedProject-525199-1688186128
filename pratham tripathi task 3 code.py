from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

# Generate RSA key pair
key = RSA.generate(2048)
public_key = key.publickey().export_key()
private_key = key.export_key()

# Generate the keys and share the public key with the intended recipient
# Sender
sender_key = RSA.generate(2048)
sender_public_key = sender_key.publickey().export_key()

# Recipient
recipient_key = RSA.import_key(sender_public_key)

# Encrypt the message using the recipient's public key
message = "Hello, this is a secure message!"
encrypted_message = encrypt_message(message, recipient_key)

# Decrypt the message using the private key
decrypted_message = decrypt_message(encrypted_message, sender_key)

# Display the decrypted message
print("Decrypted message:", decrypted_message)
