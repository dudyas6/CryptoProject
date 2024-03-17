import socket
import threading
import pickle

from algorithms import mceliece, ecdsa
from algorithms import camellia

HEADER = 64
PORT = 5057
IP = socket.gethostbyname(socket.gethostname())
ADDRESS = (IP, PORT)
FORMAT = 'utf-8'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)
mceliece_keys = mceliece.KeyGeneration(3)
public_key = mceliece_keys.GPrime
public_key_pickled = pickle.dumps(public_key)


def handle_client(connection, address):
    print(f"[Alice]: connected")
    connection.send(public_key_pickled)

    connected = True
    while connected:
        message_len = connection.recv(HEADER).decode(FORMAT)
        if message_len:
            message_len = int(message_len)
            message_bytes = connection.recv(message_len)
            message = pickle.loads(message_bytes)

            # The whole message sent by alice
            full_cipher_message, sig_key, sig_encrypted_msg, C, P, n, original_iv, cipher, cipher_key = message

            # Verify signature (using ECDSA)
            verify_key = ecdsa.verify(cipher_key, C, P, n, sig_key)
            verify_msg = ecdsa.verify(full_cipher_message, C, P, n, sig_encrypted_msg)
            verified = verify_key and verify_msg

            if verified:
                print("[Bob]: Total digital signatures is verified")
                # Decrypt McEliece secret key
                key = mceliece.decrypt_secret_key(cipher_key, mceliece_keys.S, mceliece_keys.P, mceliece_keys.H)
                print("[Bob]: Key is decrypted by mceliece algorithm")
                print(f"[Bob]: The encrypted sent message:{decode_message(cipher)}")
                # Decrypt Camellia CFB message
                message = camellia.cfb_decryption(cipher, key.encode(FORMAT), original_iv)
                print(f"[Bob]: The decrypted message: {message.decode(FORMAT)}")
            else:
                print("[Bob]: The message failed digital signature")


def start():
    try:
        server.listen()
        print(f"[Bob]: listening on ip address {IP}...")
        while True:
            connection, address = server.accept()
            thread = threading.Thread(target=handle_client, args=(connection, address))
            thread.start()
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        server.close()


def decode_message(cipher):
    decoded_message = ""
    for block in cipher:
        decoded_message += block.decode("utf-8", errors="ignore")
    return decoded_message


print(f"[Bob]: starting...")
start()
