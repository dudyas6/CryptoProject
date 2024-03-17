import os
import socket
import pickle
from algorithms import ecdsa
from algorithms import camellia
from algorithms import mceliece

HEADER = 64
PICKLE_HEADER = 4096
PORT = 5055
FORMAT = 'utf-8'
SERVER_IP = "192.168.1.27"
ADDRESS = (SERVER_IP, PORT)


def attempt_connection():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)  # Set a timeout of 10 seconds for receiving data
    try:
        client.connect(ADDRESS)
        return client
    except socket.timeout:
        print("Connection timed out. Unable to receive public key from server.")
        exit(1)


def send(message, client):
    message_length = len(message)
    message_length_byte = str(message_length).encode(FORMAT)
    message_padding_byte = b' ' * (HEADER - len(message_length_byte))
    message_length_byte = message_length_byte + message_padding_byte

    client.send(message_length_byte)
    client.send(message)


def start():
    client = attempt_connection()
    print("[Alice]: starting...")
    public_key_message = client.recv(PICKLE_HEADER)
    public_key = pickle.loads(public_key_message)

    while True:
        message = input("Enter message you want to send ")
        key = ""
        original_iv = os.urandom(16)
        while len(key) != 16:
            key = input("Enter encryption key(16 letters) you want to use: ")
            if len(key) != 16:
                print("Invalid key")

        # Encrypt the message by using Camellia algorithm, on mode OFB
        cipher_text = camellia.cfb_encryption(message.encode(FORMAT), key.encode(FORMAT), original_iv)
        full_cipher_message = b"".join(cipher_text).hex()
        # Encrypt the secret key by using McEliece algorithm
        cipher_key = mceliece.encrypt_secret_key(key, public_key)

        # Signature (using ECDSA)
        # create a curve that its equation is: y^2 = x^3 + 2x^2 + 1 over F_729787
        C = ecdsa.CurveOverFp(0, 1, 7, 729787)
        # Sign on the encrypted message by using ECDSA
        P = ecdsa.Point(1, 3)
        n = C.order(P)
        key_pair = ecdsa.generate_keypair(C, P, n)
        # sign encrypted symmetric_key
        sig_key = ecdsa.sign(cipher_key, C, P, n, key_pair)
        # sign encrypted message
        sign_encrypted_msg = ecdsa.sign(full_cipher_message, C, P, n, key_pair)

        message_packet = [full_cipher_message, sig_key, sign_encrypted_msg, C, P,
                          n, original_iv, cipher_text, cipher_key]
        message_packet = pickle.dumps(message_packet)
        send(message_packet, client)


start()
