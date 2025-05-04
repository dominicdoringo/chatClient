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

    clients    = {}  # addr → aes_key
    client_rsa = {}  # addr → rsa_pub_bytes

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)

        # Handshake: new client
        if addr not in client_rsa:
            pub_bytes = base64.b64decode(data)
            client_rsa[addr] = pub_bytes

            aes_key = cu.generate_aes_key()
            clients[addr] = aes_key

            enc_key = cu.encrypt_with_rsa(pub_bytes, aes_key)
            b64_enc  = base64.b64encode(enc_key)
            sock.sendto(b64_enc, addr)

            print(f"[+] Handshake complete with {addr}")

        # Chat: decrypt→re-encrypt→broadcast
        else:
            # 1) Decrypt incoming ciphertext
            b64_ct = data.decode('utf-8')
            try:
                plaintext = cu.decrypt_with_aes(clients[addr], b64_ct)
                print(f"[+] Decrypted from {addr}: {plaintext}")
            except Exception as e:
                print(f"[!] Failed to decrypt from {addr}: {e}")
                continue

            # 2) Re-encrypt under each recipient’s key and send
            for client_addr, aes_key in clients.items():
                if client_addr == addr:
                    continue
                new_ct = cu.encrypt_with_aes(aes_key, plaintext)
                sock.sendto(new_ct.encode('utf-8'), client_addr)

if __name__ == "__main__":
    main()
