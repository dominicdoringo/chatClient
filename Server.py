import socket
import base64
import crypto_utils as cu

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 12345
BUFFER_SIZE = 4096

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_HOST, SERVER_PORT))
    print(f"[+] Server listening on {SERVER_HOST}:{SERVER_PORT}")

    clients = {}       # addr → aes_key (bytes)
    client_rsa = {}    # addr → rsa_pub_bytes

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)

        # --- Requirement: Accept public RSA keys from multiple clients ---
        if addr not in client_rsa:
            # First packet from this addr is its RSA public key (Base64-encoded)
            pub_bytes = base64.b64decode(data)
            client_rsa[addr] = pub_bytes

            # --- Requirement: Generate a random AES key per client ---
            aes_key = cu.generate_aes_key()
            clients[addr] = aes_key

            # --- Requirement: Encrypt each AES key using client’s RSA pubkey ---
            enc_key = cu.encrypt_with_rsa(pub_bytes, aes_key)
            b64_enc = base64.b64encode(enc_key)

            # --- Requirement: Send the encrypted AES key back to the client ---
            sock.sendto(b64_enc, addr)
            print(f"[+] Handshake complete with {addr}")

        else:
            # From now on, data is an AES-encrypted, Base64-encoded chat message
            # --- Requirement: Receive encrypted chat messages from clients ---
            # --- Requirement: Broadcast each message to all other connected clients ---
            for client_addr in clients:
                if client_addr != addr:
                    sock.sendto(data, client_addr)

if __name__ == "__main__":
    main()
