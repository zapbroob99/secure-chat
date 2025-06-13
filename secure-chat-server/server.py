import socket
import threading
import json
import base64
import os
import traceback
from crypto_utils import (
    generate_dh_keys, serialize_public_key, derive_shared_key,
    encrypt_aes_gcm, decrypt_aes_gcm,
    hash_password, verify_password,
    generate_signing_keys, sign_data,
    serialize_signing_public_key_pem,
    serialize_signing_private_key_pem, load_signing_private_key_from_pem
)

HOST = '127.0.0.1'
PORT = 65432

SERVER_SIGNING_PRIVATE_KEY_FILE = "server_signing_private.pem"
SERVER_SIGNING_PUBLIC_KEY_FILE = "server_signing_public.pem"
SERVER_SIGNING_KEY_PASSWORD = None
server_signing_private_key = None

USER_DATA_FILE = "users.json"
user_credentials = {}
clients = {}

def load_user_data():
    global user_credentials
    if os.path.exists(USER_DATA_FILE):
        try:
            with open(USER_DATA_FILE, "r") as f: user_credentials = json.load(f)
            print(f"Kullanıcı verileri '{USER_DATA_FILE}' dosyasından yüklendi.")
        except Exception as e: print(f"'{USER_DATA_FILE}' yüklenirken hata: {e}. Boş başlatılıyor."); user_credentials = {}
    else: print(f"'{USER_DATA_FILE}' bulunamadı. Boş başlatılıyor."); user_credentials = {}

def save_user_data():
    global user_credentials
    try:
        with open(USER_DATA_FILE, "w") as f: json.dump(user_credentials, f, indent=4)
    except Exception as e: print(f"Kullanıcı verileri kaydedilirken hata: {e}")

def load_or_generate_server_signing_keys():
    global server_signing_private_key
    if os.path.exists(SERVER_SIGNING_PRIVATE_KEY_FILE):
        try:
            with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "rb") as f: server_signing_private_key = load_signing_private_key_from_pem(f.read(), SERVER_SIGNING_KEY_PASSWORD)
            print(f"Sunucu imzalama özel anahtarı '{SERVER_SIGNING_PRIVATE_KEY_FILE}' yüklendi.")
            if not os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE):
                with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "wb") as f: f.write(serialize_signing_public_key_pem(server_signing_private_key.public_key()))
                print(f"Sunucu imzalama genel anahtarı '{SERVER_SIGNING_PUBLIC_KEY_FILE}' oluşturuldu.")
        except Exception as e: print(f"'{SERVER_SIGNING_PRIVATE_KEY_FILE}' yüklenirken hata: {e}. Yeni üretilecek."); server_signing_private_key = None
    if not server_signing_private_key:
        print("Yeni sunucu imzalama anahtarları üretiliyor..."); priv, pub = generate_signing_keys(); server_signing_private_key = priv
        with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "wb") as f: f.write(serialize_signing_private_key_pem(priv, SERVER_SIGNING_KEY_PASSWORD))
        with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "wb") as f: f.write(serialize_signing_public_key_pem(pub))
        print("Sunucu imzalama anahtarları üretildi ve kaydedildi."); return True
    return True

def send_encrypted_message_to_client(client_socket, command_type, payload_dict):
    client_info = clients.get(client_socket)
    if not client_info or "session_key" not in client_info: return False
    message_counter = client_info.get("outgoing_message_counter", 0)
    client_info["outgoing_message_counter"] = message_counter + 1
    try:
        encrypted_payload = encrypt_aes_gcm(client_info["session_key"], json.dumps(payload_dict), message_counter)
        client_socket.sendall(f"{command_type}:{encrypted_payload}\n".encode('utf-8')); return True
    except Exception as e: print(f"Mesaj gönderirken hata ({client_info.get('username')}): {e}"); remove_client(client_socket); return False

def broadcast_message(message_content, sender_conn, sender_username):
    print(f"[BROADCAST] {sender_username}: {message_content[:30]}...")
    payload = {"sender": sender_username, "content": message_content, "type": "broadcast"}
    for sock, info in list(clients.items()):
        if sock != sender_conn and info.get("session_key") and info.get("username"):
            send_encrypted_message_to_client(sock, "BROADCAST", payload)

def remove_client(client_socket):
    if client_socket in clients: print(f"İstemci {clients.pop(client_socket).get('username', 'Bilinmeyen')} kesildi.")
    try: client_socket.close()
    except: pass

def handle_client(conn, addr):
    print(f"Yeni bağlantı: {addr}")
    clients[conn] = {"address": addr, "outgoing_message_counter": 0, "expected_incoming_message_counter": 0}
    client_info = clients[conn]
    try:
        s_dh_priv, s_dh_pub = generate_dh_keys(); s_dh_pub_bytes = serialize_public_key(s_dh_pub)
        if not server_signing_private_key: conn.sendall(b"ERR:NO_SKEY\n"); remove_client(conn); return
        sig = sign_data(server_signing_private_key, s_dh_pub_bytes)
        conn.sendall(b"DH_INIT_SERVER_PUBKEY:" + base64.b64encode(s_dh_pub_bytes) + b":" + base64.b64encode(sig) + b"\n")
        c_pubkey_data = conn.recv(2048).strip()
        if not c_pubkey_data.startswith(b"DH_CLIENT_PUBKEY:"): remove_client(conn); return
        c_dh_pub_bytes = base64.b64decode(c_pubkey_data[len(b"DH_CLIENT_PUBKEY:"):])
        sess_key = derive_shared_key(s_dh_priv, c_dh_pub_bytes)
        if sess_key is None: remove_client(conn); return
        client_info["session_key"] = sess_key
        print(f"[{addr}] Oturum anahtarı türetildi.")
        conn.sendall(b"DH_SUCCESS\n")
    except Exception as e: print(f"[{addr}] DH/Auth hatası: {e}"); traceback.print_exc(); remove_client(conn); return

    auth_user = None
    try:
        while True:
            data = conn.recv(4096)
            if not data: print(f"İstemci {addr} ({client_info.get('username')}) kapattı."); break
            messages = data.decode('utf-8').split('\n')
            for msg_str in messages:
                if not msg_str: continue
                curr_cli_info = clients.get(conn)
                if not curr_cli_info or not curr_cli_info.get("session_key"): continue
                try: cmd, enc_blob = msg_str.split(":", 1)
                except ValueError: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Invalid format."}); continue
                
                payload_str, rcv_count = decrypt_aes_gcm(curr_cli_info["session_key"], enc_blob)
                if payload_str is None: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Decryption fail."}); continue
                exp_count = curr_cli_info["expected_incoming_message_counter"]
                if rcv_count < exp_count: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Replay detected."}); continue
                curr_cli_info["expected_incoming_message_counter"] = rcv_count + 1
                payload = json.loads(payload_str)

                if cmd == "REGISTER_E2E_PUBKEY":
                    if auth_user:
                        pem = payload.get("e2e_public_key_pem")
                        if pem and auth_user in user_credentials:
                            user_credentials[auth_user]["e2e_public_key_pem"] = pem; save_user_data()
                            send_encrypted_message_to_client(conn, "REGISTER_E2E_PUBKEY_RESPONSE", {"status": "success", "message": "E2E key registered."})
                        else: send_encrypted_message_to_client(conn, "REGISTER_E2E_PUBKEY_RESPONSE", {"status": "error", "message": "Invalid request."})
                    else: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Not authenticated."})
                
                elif cmd == "GET_E2E_PUBKEY":
                    if auth_user:
                        target = payload.get("target_username")
                        udata = user_credentials.get(target)
                        if udata and udata.get("e2e_public_key_pem"):
                            send_encrypted_message_to_client(conn, "GET_E2E_PUBKEY_RESPONSE", {"status": "success", "target_username": target, "e2e_public_key_pem": udata["e2e_public_key_pem"]})
                        else: send_encrypted_message_to_client(conn, "GET_E2E_PUBKEY_RESPONSE", {"status": "error", "message": f"E2E key for '{target}' not found."})
                    else: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Not authenticated."})

                elif cmd in ["E2E_DH_INITIATE", "E2E_DH_RESPONSE", "E2E_DM_MESSAGE"]: # Yönlendirme komutları
                    if auth_user:
                        recipient_user = payload.get("to")
                        if not recipient_user: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Recipient missing."}); continue
                        
                        recipient_sock = None
                        for sock_iter, info_iter in list(clients.items()): # Alıcıyı bul
                            if info_iter.get("username") == recipient_user: recipient_sock = sock_iter; break
                        
                        if recipient_sock:
                            forward_payload = payload.copy()
                            forward_payload["from_user"] = auth_user # Göndereni ekle
                         
                            if cmd == "E2E_DH_INITIATE": forward_payload["type"] = "e2e_dh_initiate"
                            elif cmd == "E2E_DH_RESPONSE": forward_payload["type"] = "e2e_dh_response"
                            elif cmd == "E2E_DM_MESSAGE": forward_payload["type"] = "e2e_dm_message"

                            print(f"'{auth_user}' -> '{recipient_user}' için {cmd} (tip: {forward_payload['type']}) yönlendiriliyor.")
                            send_encrypted_message_to_client(recipient_sock, "INCOMING_E2E_PACKET", forward_payload)
                        else: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": f"User '{recipient_user}' not online."})
                    else: send_encrypted_message_to_client(conn, "SERVER_ERROR", {"error": "Not authenticated."})

                elif cmd == "SECURE_SIGNUP":
                    uname, passwd = payload.get("username"), payload.get("password")
                    if uname and passwd:
                        if uname in user_credentials: resp = {"status": "error", "message": "Username exists."}
                        else:
                            user_credentials[uname] = {"hashed_password": hash_password(passwd), "e2e_public_key_pem": None}; save_user_data()
                            auth_user = uname; curr_cli_info["username"] = uname
                            resp = {"status": "success", "message": "Signup OK."}
                            print(f"User '{uname}' signed up.")
                    else: resp = {"status": "error", "message": "User/Pass missing."}
                    send_encrypted_message_to_client(conn, "SECURE_SIGNUP_RESPONSE", resp)

                elif cmd == "SECURE_SIGNIN":
                    uname, passwd = payload.get("username"), payload.get("password")
                    if uname and passwd:
                        cred = user_credentials.get(uname)
                        if cred and verify_password(cred.get("hashed_password"), passwd):
                            auth_user = uname; curr_cli_info["username"] = uname
                            resp = {"status": "success", "message": "Signin OK."}
                            print(f"User '{uname}' signed in.")
                        else: resp = {"status": "error", "message": "Invalid user/pass."}
                    else: resp = {"status": "error", "message": "User/Pass missing."}
                    send_encrypted_message_to_client(conn, "SECURE_SIGNIN_RESPONSE", resp)
                
                elif cmd == "BROADCAST":
                    if auth_user:
                        content = payload.get("content")
                        if content: broadcast_message(content, conn, auth_user)
                        else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"error": "Broadcast content missing."})
                    else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"error": "Not authenticated."})
                else: send_encrypted_message_to_client(conn, "SERVER_RESPONSE", {"error": f"Unknown command: {cmd}"})
    
    except ConnectionResetError: print(f"İstemci {addr} ({curr_cli_info.get('username') if 'curr_cli_info' in locals() else 'Unauth'}) kapattı.")
    except BrokenPipeError: print(f"İstemci {addr} ({curr_cli_info.get('username') if 'curr_cli_info' in locals() else 'Unauth'}) pipe bozuk.")
    except json.JSONDecodeError as e: print(f"İstemci {addr} ({curr_cli_info.get('username') if 'curr_cli_info' in locals() else 'Unauth'}) geçersiz JSON: {e}.")
    except Exception as e: print(f"İstemci {addr} ({curr_cli_info.get('username') if 'curr_cli_info' in locals() else 'Unauth'}) hata: {e}"); traceback.print_exc()
    finally: remove_client(conn)

if __name__ == "__main__":
    load_user_data()
    if not load_or_generate_server_signing_keys(): print("Sunucu başlatılamıyor."); exit()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((HOST, PORT)); s.listen()
        print(f"Sunucu {HOST}:{PORT} dinlemede...")
        try:
            while True: conn, addr = s.accept(); threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt: print("\nSunucu kapatılıyor...")
        except Exception as e: print(f"Ana döngüde hata: {e}"); traceback.print_exc()
        finally:
            print("Bağlantılar kapatılıyor..."); 
            for sk in list(clients.keys()): remove_client(sk)
            s.close(); print("Sunucu kapatıldı.")