from Crypto.Cipher import AES
import hashlib

# Function to pad the message to make it 128 bits
def pad_message(message):
    while len(message) % 16 != 0:
        message += '@'  # Padding with '@' to make it multiple of 16
    return message

# Function to chunk the message into 128-bit sub-messages
def chunk_message(message):
    return [message[i:i+16] for i in range(0, len(message), 16)]

# Function to encrypt a message using AES-128
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)

# Function to decrypt a message using AES-128
def decrypt_message(key, encrypted_message):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(encrypted_message)

# Diffie-Hellman key exchange parameters
p = 199
g = 127

# Private keys for User A and User B
private_key_A = 57
private_key_B = 167

# Computing public values for User A and User B
public_value_A = (g ** private_key_A) % p
public_value_B = (g ** private_key_B) % p

# Computing shared key
shared_key_A = (public_value_B ** private_key_A) % p
shared_key_B = (public_value_A ** private_key_B) % p

# Transforming shared key into 128-bit key
shared_key_A_hex = ''.join(hex(ord(c))[2:].zfill(2) for c in str(shared_key_A))
shared_key_B_hex = ''.join(hex(ord(c))[2:].zfill(2) for c in str(shared_key_B))

if len(shared_key_A_hex) < 32:
    shared_key_A_hex = shared_key_A_hex + 'C' * (32 - len(shared_key_A_hex))
elif len(shared_key_A_hex) < 64:
    shared_key_A_hex = shared_key_A_hex + 'DD' * ((64 - len(shared_key_A_hex)) // 2)
else:
    shared_key_A_hex = shared_key_A_hex + 'F' * (32 - len(shared_key_A_hex))

if len(shared_key_B_hex) < 32:
    shared_key_B_hex = shared_key_B_hex + 'C' * (32 - len(shared_key_B_hex))
elif len(shared_key_B_hex) < 64:
    shared_key_B_hex = shared_key_B_hex + 'DD' * ((64 - len(shared_key_B_hex)) // 2)
else:
    shared_key_B_hex = shared_key_B_hex + 'F' * (32 - len(shared_key_B_hex))

# Encrypting the message
message = "The Mandalorian Must Always Recite, This is The Way!"
padded_message = pad_message(message)
sub_messages = chunk_message(padded_message)

encrypted_messages = []
for sub_message in sub_messages:
    key = bytes.fromhex(shared_key_A_hex)
    encrypted_message = encrypt_message(key, sub_message.encode())
    encrypted_messages.append(encrypted_message)

big_encrypted_message = b"".join(encrypted_messages)

hex_encrypted_message = big_encrypted_message.hex().upper()

# Decrypting the message
decrypted_messages = []
for i in range(0, len(big_encrypted_message), 16):
    key = bytes.fromhex(shared_key_B_hex)
    decrypted_message = decrypt_message(key, big_encrypted_message[i:i+16])
    decrypted_messages.append(decrypted_message.decode())

original_message = ''.join(decrypted_messages).rstrip('@')

print("Shared Key:", shared_key_A)
print("Encrypted Message:", hex_encrypted_message)
print("Original Message:", original_message)
