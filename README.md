# NonceSense - Secure Chat Application

**"Signal? Never Heard of It"**

## Project Overview

NonceSense is a secure client-server chat application developed in Python, designed with a strong emphasis on user privacy and data security. It implements robust cryptographic mechanisms for user authentication, secure communication channels between clients and the server, and end-to-end encrypted (E2EE) direct messaging with forward secrecy. The application allows users to register, log in, send broadcast messages to all authenticated users, and engage in private E2EE conversations with specific users where even the server cannot decipher the message content.

## Core Security Features

*   **Secure User Registration & Login:**
    *   Passwords are not stored plaintext. They are securely hashed using PBKDF2-SHA256 with a unique salt per user and a high iteration count.
    *   Login verification uses timing attack-resistant hash comparison (`hmac.compare_digest`).
*   **Authenticated & Encrypted Client-Server Channel:**
    *   **Diffie-Hellman (DH) Key Exchange:** Establishes a unique symmetric session key (`SessionKey_CS`) for each client-server connection, providing **Forward Secrecy** for this transport link.
    *   **Server Authentication:** During the DH exchange, the server signs its ephemeral DH public key with its long-term RSA private key. Clients verify this signature against the server's known public key, preventing Man-in-the-Middle (MITM) attacks on server identity.
    *   **AES-256-GCM Encryption:** All data (control messages, wrapped E2EE packets) exchanged between the client and server post-DH is encrypted and authenticated using `SessionKey_CS` and per-direction message counters.
    *   **Replay Attack Protection:** Message counters embedded in the AES-GCM nonce protect the client-server channel against replay attacks.
*   **End-to-End Encrypted (E2EE) Direct Messaging with Forward Secrecy:**
    *   **User Identity Keys:** Each user possesses a long-term RSA key pair (`E2E_Identity_Key`) for signing purposes. Public identity keys are registered with the server.
    *   **Ephemeral DH Key Exchange for E2EE Sessions:** To initiate a DM, an ephemeral DH key exchange is performed between the two clients (mediated by the server, which cannot see the DH private keys).
    *   **Authenticated DH Exchange:** Both clients sign their ephemeral DH public keys with their long-term E2EE Identity Private Keys. The peer verifies this signature, ensuring they are talking to the correct authenticated user for the E2EE DH setup.
    *   **E2EE Session Key (`E2E_SessionKey_AB`):** A unique symmetric AES key is derived from the ephemeral DH shared secret (via HKDF) for each DM conversation, providing **Forward Secrecy** for the DM content.
    *   **AES-256-GCM Message Encryption:** Actual DM messages are encrypted using the derived `E2E_SessionKey_AB` and per-E2EE-session message counters.
    *   **Server Blindness:** The server relays E2EE DH handshake packets and encrypted DM messages but **cannot decrypt the `E2E_SessionKey_AB` or the content of the E2EE messages.**
*   **Broadcast Messaging:**
    *   Authenticated users can send broadcast messages. These are encrypted between the sender and the server using `SessionKey_CS`. The server decrypts, (can read content), and then re-encrypts the message for each recipient using their respective `SessionKey_CS`.

## Technologies Used

*   **Python 3.x**
*   **Standard Libraries:** `socket`, `threading`, `json`, `base64`, `os`, `hashlib`, `hmac`, `struct`, `getpass`, `traceback`
*   **Cryptography Library (`cryptography`):**
    *   AES-256-GCM for symmetric encryption.
    *   RSA (2048-bit) with PSS padding for digital signatures.
    *   Diffie-Hellman (DH) Key Exchange (RFC 3526, 2048-bit Group 14).
    *   HKDF (HMAC-based Key Derivation Function) with SHA-256.
    *   PBKDF2-HMAC-SHA256 for password hashing.
    *   SHA-256 as the underlying hash function.
    *   Key Serialization (PEM for RSA, DER for DH public keys).

## Project Structure

The project is organized into two main, independent applications: a server and a client.

## Setup and Usage

### Prerequisites

*   Python 3.7+
*   `pip` (Python package installer)

### Server Setup

1.  Navigate to the `secure-chat-server/` directory.
2.  Create and activate a Python virtual environment (e.g., `python -m venv env_server && source env_server/bin/activate`).
3.  Install dependencies: `pip install -r requirements.txt`.
4.  Run the server: `python server.py`.
    *   On the first run, `server_signing_private.pem`, `server_signing_public.pem`, and an empty `users.json` will be created if they don't exist.
    *   **Crucial:** The `server_signing_public.pem` file must be distributed/copied to any client wishing to connect.

### Client Setup

1.  Navigate to the `secure-chat-client/` directory.
2.  Create and activate a Python virtual environment (e.g., `python -m venv env_client && source env_client/bin/activate`).
3.  Install dependencies: `pip install -r requirements.txt`.
4.  **Copy `server_signing_public.pem`:** Place the `server_signing_public.pem` file (generated by the server) into this `secure-chat-client/` directory.
5.  Run the client: `python client.py`.
    *   On the first run, `client_e2e_id_private.pem` will be generated if it doesn't exist.
    *   Follow on-screen prompts for registration or login.

### Client Commands

*   **Not Logged In:** `signup`, `signin`, `exit`, `help`
*   **Logged In:**
    *   `broadcast <message>`: Send a message to all online users.
    *   `dm <username> <message>`: Send an End-to-End Encrypted direct message. (The client handles E2EE key fetching and DH session setup automatically).
    *   `logout`: Log out from the server.
    *   `exit`: Close the client.
    *   `help`: Display available commands.

## Known Limitations

*   **CLI User Experience:** Basic CLI; incoming messages can sometimes require an "Enter" press to fully refresh the input prompt due to the blocking nature of `input()`.
*   **E2EE Identity Key Verification:** No out-of-band mechanism for users to verify the authenticity of other users' E2EE identity public keys (e.g., safety number comparison). Clients trust the server for this distribution.
*   **Client-Side E2EE Private Key Storage:** The E2EE identity private key is stored in a local PEM file. Its protection relies on the user's local file system security. No advanced backup or multi-device synchronization features.
*   **Offline E2EE DMs:** The current implementation requires both users to be online for the initial E2EE DH handshake. Messages are not queued by the server if a recipient is offline.
*   **No E2EE Group Chat:** Only 1-to-1 E2EE DMs are supported.
*   **DoS Resilience:** The server's resilience against sophisticated Denial of Service attacks (e.g., resource exhaustion via rapid connections or cryptographic operations) could be improved with rate limiting and other hardening techniques.

## Potential Improvements

*   **GUI/Advanced CLI:** Develop a graphical user interface (e.g., Tkinter, PyQt) or a more responsive CLI (e.g., `prompt_toolkit`) for an enhanced user experience.
*   **Advanced E2EE Protocol:** Integrate a protocol like the Signal Protocol (X3DH, Double Ratchet) for stronger E2EE properties, including better asynchronicity and post-compromise security.
*   **Key Verification Mechanisms:** Implement safety numbers or QR code scanning for out-of-band verification of E2EE identity keys.
*   **Secure Offline E2EE Messaging:** Design a server-side store-and-forward mechanism for E2EE messages.
*   **E2EE Group Chat Functionality.**
*   **Secure File Transfer (E2EE).**



