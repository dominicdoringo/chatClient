# chatClient
# Secure UDP Chat

A simple Python-based chat application that uses a hybrid RSA/AES scheme over UDP for confidentiality.

## Prerequisites

- **Windows 10/11**, macOS, or Linux  
- **Python 3.7+** installed and on your PATH  
- **PyCryptodome** library  
- **prompt toolkit** library  
- **Visual Studio Code** Text and Code editor  

```bash
pip install pycryptodome
pip install prompt_toolkit

1. Start the server by opening a new terminal on Visual Studio code. 
    - python Server.py

2. Open two more split terminals on visual studio code.
    - both terminals put: python Client.py

    Each client will:
    Generate its own RSA keypair.
    Send the public key to the server.
    Receive and decrypt a unique AES key.
    Enter a prompt where you can type messages.

    Type a message into Client #2 and press Enter.
    You’ll see it appear in the other client windows.

    Cryptographic Design Choices

    Hybrid Encryption

        RSA-2048 for key exchange:

            Each client generates a fresh 2048-bit RSA keypair on startup.

            The public key is sent to the server in Base64.

        AES-128 (CBC mode) for bulk encryption:

            Server generates a new 16-byte (128-bit) AES key per client.

            The AES key is encrypted under the client’s RSA public key and sent back.

            All chat messages use AES-CBC with a random IV per message and PKCS#7 padding.

    Base64 Encoding

        All RSA blobs and AES ciphertexts (IV‖ciphertext) are Base64-encoded so they can safely travel as text in UDP packets.

    Server Relay Model

        The server decrypts each incoming ciphertext (using the sender’s AES key), then re-encrypts under each recipient’s AES key before forwarding.

        This ensures every client can successfully decrypt messages intended for them.

Assumptions & Limitations

    Trust Model:

        The server is trusted with plaintext during the relay phase (it sees every message in clear).

        Clients implicitly trust any peer that completes the RSA handshake.

    No Authentication or Integrity Checks:

        There is no HMAC or signature on chat messages—modification or replay by an attacker is not detected.

        An active attacker could forge or replay messages.

    UDP Delivery:

        Messages may be lost, duplicated, or arrive out of order. There is no retransmission logic.

    No Persistence:

        Chat history is not saved; once clients or the server restart, all state is lost.

    Single-Threaded Server:

        The server handles all clients in a single loop; it may become a bottleneck as the number of clients grows.

    No Configuration Options:

        Host, port, and other parameters are hard-coded. (You can extend with argparse for flexibility.)