
"""
Client.py

Terminal-based secure UDP chat client 
"""

import socket
import threading
import base64
import crypto_utils as cu
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

# Server config
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
BUFFER_SIZE = 4096

def listen_loop(sock, aes_key):
    """
    Background thread: receive AES-encrypted Base64 packets,
    decrypt them, and print above the prompt.
    """
    while True:
        try:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            msg = cu.decrypt_with_aes(aes_key, data.decode('utf-8'))
            # A newline lets prompt_toolkit re-draw the prompt cleanly
            print(f"\nFriend: {msg}")
        except Exception:
            continue

def main():
    # 1) Handshake: RSA keypair → send pubkey → recv & decrypt AES key
    priv, pub = cu.generate_rsa_keypair()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(base64.b64encode(pub), (SERVER_HOST, SERVER_PORT))

    enc_key_b64, _ = sock.recvfrom(BUFFER_SIZE)
    aes_key = cu.decrypt_with_rsa(priv, base64.b64decode(enc_key_b64))
    print("[+] Secure channel established. Start typing below.\n")

    # 2) Start listener thread
    threading.Thread(target=listen_loop, args=(sock, aes_key), daemon=True).start()

    # 3) Use prompt_toolkit so incoming prints don't break your input
    session = PromptSession('You: ')
    with patch_stdout():
        while True:
            try:
                # This prompt will re-draw after any print above
                msg = session.prompt()
                if not msg.strip():
                    continue
                ct = cu.encrypt_with_aes(aes_key, msg)
                sock.sendto(ct.encode('utf-8'), (SERVER_HOST, SERVER_PORT))
            except (KeyboardInterrupt, EOFError):
                print("\nExiting…")
                break

if __name__ == '__main__':
    main()
