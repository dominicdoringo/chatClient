import socket
import threading
import base64
import crypto_utils as cu

SERVER_HOST = '127.0.0.1'   # or replace with your server’s IP
SERVER_PORT = 12345
BUFFER_SIZE = 4096

def listen_loop(sock, aes_key):
    """
    Thread: receive AES-encrypted Base64 messages and decrypt/display them.
    """
    while True:
        data, _ = sock.recvfrom(BUFFER_SIZE)
        try:
            # --- Requirement: Decrypt incoming messages with AES key ---
            plaintext = cu.decrypt_with_aes(aes_key, data.decode('utf-8'))
            # --- Requirement: Display chat messages in real time ---
            print(f"\nFriend: {plaintext}")
        except Exception:
            # ignore bad/decryption errors
            continue

def main():
    # --- Requirement: Generate an RSA key pair at startup ---
    priv, pub = cu.generate_rsa_keypair()

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # --- Requirement: Send the public key to the server (Base64-encoded) ---
    sock.sendto(base64.b64encode(pub), (SERVER_HOST, SERVER_PORT))

    # --- Requirement: Receive & decrypt the AES symmetric key using the private key ---
    enc_key_b64, _ = sock.recvfrom(BUFFER_SIZE)
    enc_key = base64.b64decode(enc_key_b64)
    aes_key = cu.decrypt_with_rsa(priv, enc_key)
    print("[+] Received AES key; secure channel established.")

    # Start thread to listen for incoming messages
    listener = threading.Thread(
        target=listen_loop, args=(sock, aes_key), daemon=True
    )
    listener.start()

    # Main loop: read user input, encrypt, and send
    while True:
        msg = input("You: ")
        if not msg:
            continue
        # --- Requirement: Encrypt outgoing messages with AES key ---
        b64_ct = cu.encrypt_with_aes(aes_key, msg)
        sock.sendto(b64_ct.encode('utf-8'), (SERVER_HOST, SERVER_PORT))

if __name__ == "__main__":
    main()
