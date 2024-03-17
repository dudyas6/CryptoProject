import os
import socket
import pickle

import numpy as np

from algorithms import ecdsa, camellia, mceliece
import PySimpleGUI as sg

FORMAT = 'utf-8'
mceliece_keys = mceliece.KeyGeneration(3)
camellia_key = 0x2BD6459F82C5B300952C49104881FF48
encrypted_camellia_key = 0
ecdsa_signature = 0
iv = 0x0000000000000000
EMAIL_SIMULATION = []


def handleInitilizationVector(iv):
    if len(iv) != 16:
        return os.urandom(16)
    return iv.encode(FORMAT)


def handleKeyValue(key):
    if len(key) != 16:
        return str(os.urandom(8).hex()[:16])
    return key


def getPublicKey():
    return mceliece_keys.GPrime


def throwAuthenticationError(error):
    window["-PLAINTEXT-"].update(error)


sg.theme('SystemDefaultForReal')

# First the window layout in 2 columns
encryption_column = [
    [
        sg.Text("Plaintext"),

    ],
    [
        sg.Multiline("Hello World", size=(60, 10), key="-PLAINTEXT-")
    ],
    [
        sg.Button("Encrypt + Send", size=(14, 1)),
        sg.Button("Clear", key='-PLAIN_CLEAR-'),
        sg.Button("Copy", key='-PLAIN_COPY-'),
        sg.Input(key='-IMPORT_TXT-', visible=False, enable_events=True), sg.FileBrowse()
    ],
    [
        sg.Text("Decryption Verified: "),
        sg.Text("False", size=(40, 1), key="-VERIFIED-", tooltip="Verified", font=("Helvetica", 10), text_color="red"),
    ],
    [
        sg.Text("Camellia Key: "),
        sg.Push(),
        sg.Input("ABCDEFGH12345678", size=(40, 1), key="-CAMELLIA_KEY-",
                 tooltip="Enter key of length 16, only a-z A-Z 0-9 allowed",
                 font=("Helvetica", 10)),
        sg.Button("Copy", key="-CAMELLIA_KEY_COPY-"),

    ],
    [
        sg.Text("Initialization Vector"),
        sg.VSeparator(),
        sg.Text("Current: " + str(hex(iv)), key="-CURRENT_IV-"),
    ],
    [
        sg.Input(size=(40, 1), key="-IV-"),
    ],

]
# First the window layout in 2 columns
decryption_column = [
    [
        sg.Text("Ciphertext"),

    ],
    [
        sg.Multiline(size=(60, 10), key="-CIPHERTEXT-")
    ],
    [
        sg.Button("Decrypt", size=(10, 1)),
        sg.Button("Clear", key='-CIPHER_CLEAR-'),
        sg.Button("Copy", key='-CIPHER_COPY-'),
    ],
    [
        sg.Text("Signature: "),
        sg.Push(),
        sg.Input(size=(40, 1), key="-SIGNATURE-", tooltip="Signature", font=("Helvetica", 10)),
        sg.Button("Copy", key="-SIGNATURE_COPY-"),
    ],
    [
        sg.Text("Public Key: "),
        sg.Push(),
        sg.Input(size=(40, 1), key="-ECDSA_PUBLIC_KEY-", tooltip="Public Key", font=("Helvetica", 10)),
        sg.Button("Copy", key="-ECDSA_PUBLIC_KEY_COPY-"),

    ],
    [
        sg.Text("Initialization Vector"),
        sg.VSeparator(),
        sg.Text("Current: " + str(hex(iv)), key="-CURRENT_DECRYPTION_IV-"),
    ],
    [
        sg.Input(size=(40, 1), key="-DECRYPTION_IV-"),
    ],
    [
        sg.Button("Export Encryption")
    ]
]

# GUI Layout
layout = [
    [
        sg.vtop(sg.Column(encryption_column)),
        sg.VSeperator(),
        sg.vtop(sg.Column(decryption_column)),
    ],

]

# Create the window
window = sg.Window("Email exchange system - Encryption/Decryption using Camellia CFB Mode", layout, margins=(10, 20))

# Event loop

while True:
    event, values = window.read()

    if event == sg.WINDOW_CLOSED:
        break

    elif event == "-IMPORT_TXT-":
        path = values["-IMPORT_TXT-"]
        try:
            with open(path, "r") as file:
                content = file.read()
            window["-PLAINTEXT-"].update(content)
        except FileNotFoundError:
            sg.popup_error("File not found.")

    elif event == "Encrypt + Send":
        plaintext = values["-PLAINTEXT-"]
        iv = handleInitilizationVector(values["-IV-"])
        key = handleKeyValue(values["-CAMELLIA_KEY-"])
        public_key = getPublicKey()

        # Encrypt the message by using Camellia algorithm, on mode OFB
        cipher_text = camellia.cfb_encryption(plaintext.encode(FORMAT), key.encode(FORMAT), iv)
        full_cipher_message = b"".join(cipher_text).hex()
        # Encrypt the secret key by using McEliece algorithm
        cipher_key = mceliece.encrypt_secret_key(key, public_key)

        C = ecdsa.CurveOverFp(0, 1, 7, 729787)
        P = ecdsa.Point(1, 3)
        n = C.order(P)
        key_pair = ecdsa.generate_keypair(C, P, n)
        sig_key = ecdsa.sign(cipher_key, C, P, n, key_pair)
        sign_encrypted_msg = ecdsa.sign(full_cipher_message, C, P, n, key_pair)
        email_packet = [full_cipher_message, sig_key, sign_encrypted_msg, C, P,
                        n, iv, cipher_text, cipher_key]
        EMAIL_SIMULATION = email_packet
        # email_packet = [full_cipher_message, sig_key, sign_encrypted_msg, C, P,
        #                   n, iv, cipher_text, cipher_key]
        # message_packet = pickle.dumps(message_packet)

        window["-CIPHERTEXT-"].update(full_cipher_message)
        window["-CAMELLIA_KEY-"].update(f"0x{str(key)}")
        window["-IV-"].update(f"{str(iv.hex().upper())}")
        window["-DECRYPTION_IV-"].update(f"{str(iv.hex().upper())}")
        window["-CURRENT_IV-"].update("Current: " + f"0x{str(iv.hex().upper())}")
        window["-CURRENT_DECRYPTION_IV-"].update("Current: " + f"0x{str(iv.hex().upper())}")
        window["-SIGNATURE-"].update(str(sign_encrypted_msg))
        window["-ECDSA_PUBLIC_KEY-"].update(str(sig_key))

    elif event == "Decrypt":

        if values["-CIPHERTEXT-"]:
            # The whole message sent by alice
            full_cipher_message, sig_key, sig_encrypted_msg, C, P, n, original_iv, cipher, cipher_key = EMAIL_SIMULATION

            # Verify signature (using ECDSA)
            verify_key = ecdsa.verify(cipher_key, C, P, n, sig_key)
            verify_msg = ecdsa.verify(full_cipher_message, C, P, n, sig_encrypted_msg)
            verified = verify_key and verify_msg
            if verified:
                window["-VERIFIED-"].update(str(verified), text_color="green")
                key = mceliece.decrypt_secret_key(cipher_key, mceliece_keys.S, mceliece_keys.P, mceliece_keys.H)
                message = camellia.cfb_decryption(cipher, key.encode(FORMAT), original_iv)
                window["-CIPHERTEXT-"].update(message.decode(FORMAT))
            else:
                throwAuthenticationError("Authentication error: The verification process failed.")
                window["-VERIFIED-"].update(str(verified), text_color="red")

    elif event == '-CIPHER_COPY-':
        text_to_copy = values['-CIPHERTEXT-']
        sg.clipboard_set(text_to_copy)

    elif event == '-PLAIN_COPY-':
        text_to_copy = values['-PLAINTEXT-']
        sg.clipboard_set(text_to_copy)

    elif event == '-SIGNATURE_COPY-':
        text_to_copy = values['-SIGNATURE-']
        sg.clipboard_set(text_to_copy)

    elif event == '-ECDSA_PUBLIC_KEY_COPY-':
        text_to_copy = values['-ECDSA_PUBLIC_KEY-']
        sg.clipboard_set(text_to_copy)

    elif event == '-CAMELLIA_KEY_COPY-':
        text_to_copy = values['-IDEA_KEY-']
        sg.clipboard_set(text_to_copy)

    elif event == '-CIPHER_CLEAR-':
        window['-CIPHERTEXT-'].update('')

    elif event == '-PLAIN_CLEAR-':
        window['-PLAINTEXT-'].update('')

    elif event == "Export Encryption":
        # iv_text = values["-DECRYPTION_IV-"]
        # # Export ciphertext
        # with open("Ciphertext.txt", "w") as f:
        #     f.write(ciphertext.encode("utf-8").hex())
        # # Export the encrypted IDEA key, the encrypted IDEA key signature, and the IV
        # with open("Merkle-Hellman-public-key.txt", "w") as f:
        #     f.write(str(hex(encrypted_IDEA_key)))
        # with open("Enryption-signature.txt", "w") as f:
        #     f.write(str(ECDSA_signature.hex()))
        # with open("Encryption-IV.txt", "w") as f:
        #     f.write(iv_text)
        pass

# Close the window
window.close()
