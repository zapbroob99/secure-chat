import socket
import threading
import json
import getpass
import base64
import time
import os
import traceback
from crypto_utils import (
    generate_dh_keys, serialize_public_key, derive_shared_key,
    encrypt_aes_gcm, decrypt_aes_gcm,
    load_signing_public_key_from_pem, verify_signature,
    generate_signing_keys, serialize_signing_public_key_pem,
    serialize_signing_private_key_pem, load_signing_private_key_from_pem,
    sign_data,
)

HOST = '127.0.0.1'
PORT = 65432
SERVER_SIGNING_PUBLIC_KEY_FILE = "server_signing_public.pem"
CLIENT_E2E_IDENTITY_PRIVATE_KEY_FILE = "client_e2e_id_private.pem"
CLIENT_E2E_KEY_PASSWORD = None

server_signing_public_key = None
my_e2e_identity_private_key = None
my_e2e_identity_public_key_pem = None

active_e2e_dm_sessions = {}
received_e2e_identity_public_keys_cache = {}

client_socket = None
session_key = None
is_authenticated = False
username_cache = None

outgoing_message_counter_to_server = 0
expected_incoming_message_counter_from_server = 0
e2e_key_registered_this_session = False

e2e_pubkey_requests = {}
e2e_pubkey_requests_lock = threading.Lock()

pending_dh_initiates = {}
pending_dh_initiates_lock = threading.Lock()

class TermColors:
    HEADER = '\033[95m'; OKBLUE = '\033[94m'; OKCYAN = '\033[96m'; OKGREEN = '\033[92m'
    WARNING = '\033[93m'; FAIL = '\033[91m'; ENDC = '\033[0m'; BOLD = '\033[1m'; UNDERLINE = '\033[4m'
IS_WINDOWS = os.name == 'nt'
def color_text(text, color_code): return text if IS_WINDOWS else f"{color_code}{text}{TermColors.ENDC}"
def print_system_message(message, level="info"):
    colors = {"error": TermColors.FAIL, "warning": TermColors.WARNING, "success": TermColors.OKGREEN, "info": TermColors.OKBLUE, "header":TermColors.HEADER}
    print(f"\n{color_text(f'[{level.upper()}]', colors.get(level, TermColors.OKBLUE))} {message}")

def load_server_verification_key():
    global server_signing_public_key
    if not os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE): print_system_message(f"Server verification file ('{SERVER_SIGNING_PUBLIC_KEY_FILE}') not found.", "error"); return False
    try:
        with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "rb") as f: server_signing_public_key = load_signing_public_key_from_pem(f.read())
        print_system_message(f"Server verification key '{SERVER_SIGNING_PUBLIC_KEY_FILE}' loaded.", "info"); return True
    except Exception as e: print_system_message(f"Failed to load server verification key: {e}", "error"); traceback.print_exc(); return False

def load_or_generate_my_e2e_identity_keys():
    global my_e2e_identity_private_key, my_e2e_identity_public_key_pem
    if os.path.exists(CLIENT_E2E_IDENTITY_PRIVATE_KEY_FILE):
        try:
            with open(CLIENT_E2E_IDENTITY_PRIVATE_KEY_FILE, "rb") as f: pem_data = f.read()
            my_e2e_identity_private_key = load_signing_private_key_from_pem(pem_data, CLIENT_E2E_KEY_PASSWORD)
            my_e2e_identity_public_key_pem = serialize_signing_public_key_pem(my_e2e_identity_private_key.public_key()).decode('utf-8')
            print_system_message(f"Personal E2EE identity keys loaded from '{CLIENT_E2E_IDENTITY_PRIVATE_KEY_FILE}'.", "info"); return True
        except Exception as e: print_system_message(f"Error loading '{CLIENT_E2E_IDENTITY_PRIVATE_KEY_FILE}': {e}. Generating new keys.", "warning"); my_e2e_identity_private_key = None
    print_system_message("Generating new personal E2EE identity key pair...", "info")
    try:
        my_e2e_identity_private_key, public_key = generate_signing_keys()
        my_e2e_identity_public_key_pem = serialize_signing_public_key_pem(public_key).decode('utf-8')
        with open(CLIENT_E2E_IDENTITY_PRIVATE_KEY_FILE, "wb") as f: f.write(serialize_signing_private_key_pem(my_e2e_identity_private_key, CLIENT_E2E_KEY_PASSWORD))
        print_system_message(f"Personal E2EE identity keys generated and saved to '{CLIENT_E2E_IDENTITY_PRIVATE_KEY_FILE}'.", "success"); return True
    except Exception as e: print_system_message(f"Error generating/saving personal E2EE identity keys: {e}", "error"); traceback.print_exc(); return False

def send_secure_command(sock, command_type, payload_dict):
    global outgoing_message_counter_to_server
    current_sess_key = session_key
    if not current_sess_key: print_system_message("No session key. Cannot send message.", "error"); return False
    current_counter = outgoing_message_counter_to_server; outgoing_message_counter_to_server += 1
    try:
        enc_payload = encrypt_aes_gcm(current_sess_key, json.dumps(payload_dict), current_counter)
        sock.sendall(f"{command_type}:{enc_payload}\n".encode('utf-8')); return True
    except socket.error as se: print_system_message(f"Socket error sending message ({command_type}): {se}", "error"); outgoing_message_counter_to_server = current_counter; return False
    except Exception as e: print_system_message(f"General error sending message ({command_type}): {e}", "error"); traceback.print_exc(); outgoing_message_counter_to_server = current_counter; return False

def register_my_e2e_identity_key_with_server():
    global e2e_key_registered_this_session
    if my_e2e_identity_public_key_pem and client_socket and session_key and is_authenticated:
        if not e2e_key_registered_this_session:
            print_system_message("Registering personal E2EE identity public key with server...", "info")
            send_secure_command(client_socket, "REGISTER_E2E_PUBKEY", {"e2e_public_key_pem": my_e2e_identity_public_key_pem})

def request_e2e_identity_public_key_and_wait(target_username, timeout=10.0):
    global received_e2e_identity_public_keys_cache, e2e_pubkey_requests
    if target_username in received_e2e_identity_public_keys_cache: return received_e2e_identity_public_keys_cache[target_username]
    event_to_wait_on = None; new_request_sent = False
    with e2e_pubkey_requests_lock:
        req_info = e2e_pubkey_requests.get(target_username)
        if req_info and req_info["status"] == "pending": event_to_wait_on = req_info["event"]
        elif not req_info or req_info["status"] == "failed":
            event_to_wait_on = threading.Event(); e2e_pubkey_requests[target_username] = {"event": event_to_wait_on, "status": "pending"}
            if send_secure_command(client_socket, "GET_E2E_PUBKEY", {"target_username": target_username}): new_request_sent = True
            else: e2e_pubkey_requests[target_username]["status"] = "failed"; return None
        else:
             if target_username in received_e2e_identity_public_keys_cache: return received_e2e_identity_public_keys_cache[target_username]
             event_to_wait_on = threading.Event(); e2e_pubkey_requests[target_username] = {"event": event_to_wait_on, "status": "pending"}
             send_secure_command(client_socket, "GET_E2E_PUBKEY", {"target_username": target_username}); new_request_sent = True
    if event_to_wait_on:
        if not new_request_sent: print_system_message(f"E2EE public key request for '{target_username}' already pending.", "info")
        else: print_system_message(f"Requesting E2EE identity public key for '{target_username}' from server...", "info")
        if event_to_wait_on.wait(timeout=timeout):
            with e2e_pubkey_requests_lock: e2e_pubkey_requests.pop(target_username, None)
            if target_username in received_e2e_identity_public_keys_cache: return received_e2e_identity_public_keys_cache[target_username]
            else: print_system_message(f"Key for '{target_username}' was expected but not found in cache after event.", "error"); return None
        else:
            print_system_message(f"Timeout waiting for E2EE public key for '{target_username}'.", "warning")
            with e2e_pubkey_requests_lock: e2e_pubkey_requests.pop(target_username, None)
            return None
    return None

def _process_pending_dh_initiate(from_user):
    global pending_dh_initiates, active_e2e_dm_sessions
    with pending_dh_initiates_lock: pending_data = pending_dh_initiates.pop(from_user, None)
    if not pending_data: return
    print_system_message(f"Processing pending E2EE DH initiate from '{from_user}'...", "info")
    payload = pending_data["payload"]
    peer_ephemeral_dh_pub_bytes_b64 = payload.get("ephemeral_dh_pub_key_b64")
    signature_b64 = payload.get("signature_b64")
    peer_identity_pub_key_pem = received_e2e_identity_public_keys_cache.get(from_user)
    if not (peer_ephemeral_dh_pub_bytes_b64 and signature_b64 and peer_identity_pub_key_pem): print_system_message(f"Missing data for pending DH initiate from '{from_user}'.", "error"); return
    try:
        peer_identity_pub_key = load_signing_public_key_from_pem(peer_identity_pub_key_pem)
        peer_ephemeral_dh_pub_bytes = base64.b64decode(peer_ephemeral_dh_pub_bytes_b64); signature = base64.b64decode(signature_b64)
        if not verify_signature(peer_identity_pub_key, signature, peer_ephemeral_dh_pub_bytes): print_system_message(f"E2EE DH initiate signature verification FAILED for '{from_user}'.", "error"); return
        my_eph_priv_dh, my_eph_pub_dh = generate_dh_keys(); my_eph_pub_dh_bytes = serialize_public_key(my_eph_pub_dh)
        e2e_session_key_ab = derive_shared_key(my_eph_priv_dh, peer_ephemeral_dh_pub_bytes)
        if e2e_session_key_ab is None: print_system_message(f"Failed to derive E2EE session key with '{from_user}' (pending DH).", "error"); return
        active_e2e_dm_sessions[from_user] = {"key": e2e_session_key_ab, "send_counter": 0, "recv_counter": 0, "status": "established"}
        print_system_message(f"E2EE DH session established with '{from_user}' (responded to pending initiate).", "success")
        my_signature_on_eph_dh = sign_data(my_e2e_identity_private_key, my_eph_pub_dh_bytes)
        response_payload = {"to": from_user, "ephemeral_dh_pub_key_b64": base64.b64encode(my_eph_pub_dh_bytes).decode(), "signature_b64": base64.b64encode(my_signature_on_eph_dh).decode()}
        send_secure_command(client_socket, "E2E_DH_RESPONSE", response_payload)
        print_system_message(f"Sent E2EE DH response to '{from_user}' (for pending initiate).", "info")
    except Exception as e: print_system_message(f"Error processing pending E2E_DH_INITIATE from '{from_user}': {e}", "error"); traceback.print_exc()

def receive_messages(sock):
    global is_authenticated, expected_incoming_message_counter_from_server, received_e2e_identity_public_keys_cache, e2e_key_registered_this_session, e2e_pubkey_requests, active_e2e_dm_sessions, pending_dh_initiates
    try:
        while True:
            data = sock.recv(4096)
            if not data: print_system_message("Connection closed by server.", "warning"); e2e_key_registered_this_session = False; break
            messages = data.decode('utf-8').split('\n')
            for msg_str in messages:
                if not msg_str: continue
                try: command, blob = msg_str.split(":", 1)
                except ValueError: print_system_message(f"Invalid message format from server: {msg_str}", "error"); continue
                if command == "DH_SUCCESS": print_system_message("DH key exchange successful!", "success"); continue
                current_sess_key = session_key
                if not current_sess_key: print_system_message("No session key, cannot decrypt message.", "error"); continue
                payload_str, rcv_serv_count = decrypt_aes_gcm(current_sess_key, blob)
                if payload_str is None: print_system_message(f"Failed to decrypt message (command: {command})", "error"); continue
                if rcv_serv_count < expected_incoming_message_counter_from_server: print_system_message(f"Replay attack detected from server! Expected: {expected_incoming_message_counter_from_server}, Got: {rcv_serv_count}", "warning"); continue
                expected_incoming_message_counter_from_server = rcv_serv_count + 1
                payload = json.loads(payload_str)

                if command in ["SECURE_SIGNUP_RESPONSE", "SECURE_SIGNIN_RESPONSE"]:
                    status, message = payload.get("status"), payload.get("message")
                    if status == "success": print_system_message(message, "success"); is_authenticated = True; register_my_e2e_identity_key_with_server()
                    else: print_system_message(message, "error"); is_authenticated = False; e2e_key_registered_this_session = False
                elif command == "BROADCAST": print(f"\n{color_text('[BROADCAST]', TermColors.HEADER)} {color_text(payload.get('sender'), TermColors.OKGREEN)}{TermColors.BOLD}:{TermColors.ENDC} {payload.get('content')}")
                elif command == "REGISTER_E2E_PUBKEY_RESPONSE":
                    level = "success" if payload.get("status") == "success" else "error"; print_system_message(f"E2EE Key Registration: {payload.get('message')}", level)
                    if payload.get("status") == "success": e2e_key_registered_this_session = True
                    else: e2e_key_registered_this_session = False
                elif command == "GET_E2E_PUBKEY_RESPONSE":
                    target = payload.get("target_username")
                    with e2e_pubkey_requests_lock: req_info = e2e_pubkey_requests.get(target)
                    if payload.get("status") == "success":
                        received_e2e_identity_public_keys_cache[target] = payload.get("e2e_public_key_pem")
                        if req_info: req_info["status"] = "success"
                        print_system_message(f"E2EE identity key for '{target}' cached.", "info")
                        _process_pending_dh_initiate(target) 
                    else:
                        if req_info: req_info["status"] = "failed"
                        print_system_message(f"Failed to get E2EE key for '{target}': {payload.get('message')}", "error")
                    if req_info and req_info.get("event"): req_info["event"].set()
                
                elif command == "INCOMING_E2E_PACKET":
                    e2e_type = payload.get("type"); from_user = payload.get("from_user")
                    if not my_e2e_identity_private_key: print_system_message(f"Received E2EE packet from '{from_user}', but no personal identity key loaded!", "error"); continue
                    if e2e_type == "e2e_dh_initiate":
                        print_system_message(f"Received E2EE DH initiate request from '{from_user}'.", "info")
                        peer_id_pub_pem = received_e2e_identity_public_keys_cache.get(from_user)
                        if not peer_id_pub_pem:
                            print_system_message(f"Identity key for '{from_user}' not in cache. Requesting from server...", "info")
                            with pending_dh_initiates_lock: pending_dh_initiates[from_user] = {"payload": payload, "status": "pending_peer_key"}
                            request_e2e_identity_public_key_and_wait(from_user) 
                        else:
                            peer_ephemeral_dh_pub_bytes_b64 = payload.get("ephemeral_dh_pub_key_b64"); signature_b64 = payload.get("signature_b64")
                            if not (peer_ephemeral_dh_pub_bytes_b64 and signature_b64): print_system_message(f"Missing data in DH initiate from '{from_user}'.", "error"); continue
                            try:
                                peer_identity_pub_key = load_signing_public_key_from_pem(peer_id_pub_pem)
                                peer_ephemeral_dh_pub_bytes = base64.b64decode(peer_ephemeral_dh_pub_bytes_b64); signature = base64.b64decode(signature_b64)
                                if not verify_signature(peer_identity_pub_key, signature, peer_ephemeral_dh_pub_bytes): print_system_message(f"E2EE DH initiate signature verification FAILED for '{from_user}'.", "error"); continue
                                print_system_message(f"E2EE DH initiate signature from '{from_user}' verified.", "info")
                                my_eph_priv_dh, my_eph_pub_dh = generate_dh_keys(); my_eph_pub_dh_bytes = serialize_public_key(my_eph_pub_dh)
                                e2e_session_key_ab = derive_shared_key(my_eph_priv_dh, peer_ephemeral_dh_pub_bytes)
                                if e2e_session_key_ab is None: print_system_message(f"Failed to derive E2EE session key with '{from_user}' (DH).", "error"); continue
                                active_e2e_dm_sessions[from_user] = {"key": e2e_session_key_ab, "send_counter": 0, "recv_counter": 0, "status": "established"}
                                print_system_message(f"E2EE DH session established with '{from_user}' (as responder).", "success")
                                my_signature_on_eph_dh = sign_data(my_e2e_identity_private_key, my_eph_pub_dh_bytes)
                                response_payload = {"to": from_user, "ephemeral_dh_pub_key_b64": base64.b64encode(my_eph_pub_dh_bytes).decode(), "signature_b64": base64.b64encode(my_signature_on_eph_dh).decode()}
                                send_secure_command(client_socket, "E2E_DH_RESPONSE", response_payload)
                                print_system_message(f"Sent E2EE DH response to '{from_user}'.", "info")
                            except Exception as e: print_system_message(f"Error processing E2E_DH_INITIATE from '{from_user}': {e}", "error"); traceback.print_exc()
                    elif e2e_type == "e2e_dh_response":
                        print_system_message(f"Received E2EE DH response from '{from_user}'.", "info")
                        peer_eph_dh_pub_b64 = payload.get("ephemeral_dh_pub_key_b64"); sig_b64 = payload.get("signature_b64")
                        sess_build_info = active_e2e_dm_sessions.get(from_user) 
                        if not sess_build_info or sess_build_info.get("status") != "initiating_dh": print_system_message(f"Received E2EE DH response from '{from_user}', but no pending initiation info.", "error"); continue
                        peer_id_pub_pem = sess_build_info.get("peer_e2e_identity_pub_key_pem")
                        if not peer_id_pub_pem: print_system_message(f"Missing peer identity key for DH response from '{from_user}'.", "error"); continue
                        try:
                            peer_id_pub = load_signing_public_key_from_pem(peer_id_pub_pem)
                            peer_eph_dh_pub_bytes = base64.b64decode(peer_eph_dh_pub_b64); sig = base64.b64decode(sig_b64)
                            if not verify_signature(peer_id_pub, sig, peer_eph_dh_pub_bytes): print_system_message(f"E2EE DH response signature verification FAILED for '{from_user}'.", "error"); active_e2e_dm_sessions.pop(from_user,None); continue
                            print_system_message(f"E2EE DH response signature from '{from_user}' verified.", "info")
                            my_eph_priv = sess_build_info["dh_ephemeral_priv_key"]
                            e2e_sess_key = derive_shared_key(my_eph_priv, peer_eph_dh_pub_bytes)
                            if e2e_sess_key is None: print_system_message(f"Failed to derive E2EE session key with '{from_user}' (DH response).", "error"); active_e2e_dm_sessions.pop(from_user,None); continue
                            initial_msg = sess_build_info.get("initial_message_to_send")
                            active_e2e_dm_sessions[from_user] = {"key": e2e_sess_key, "send_counter": 0, "recv_counter": 0, "status": "established"}
                            print_system_message(f"E2EE DH session established with '{from_user}' (as initiator).", "success")
                            if initial_msg:
                                print_system_message(f"DH complete, sending pending initial E2EE message to '{from_user}'...", "info")
                                current_send_ctr = active_e2e_dm_sessions[from_user]["send_counter"]
                                enc_e2e_msg_b64 = encrypt_aes_gcm(e2e_sess_key, initial_msg, current_send_ctr)
                                active_e2e_dm_sessions[from_user]["send_counter"] = current_send_ctr + 1
                                e2e_msg_payload = {"to": from_user, "e2e_encrypted_content_b64": enc_e2e_msg_b64}
                                send_secure_command(client_socket, "E2E_DM_MESSAGE", e2e_msg_payload)
                        except Exception as e: print_system_message(f"Error processing E2E_DH_RESPONSE from '{from_user}': {e}", "error"); traceback.print_exc(); active_e2e_dm_sessions.pop(from_user,None)
                    elif e2e_type == "e2e_dm_message":
                        enc_content_b64 = payload.get("e2e_encrypted_content_b64"); sess_info = active_e2e_dm_sessions.get(from_user)
                        if sess_info and sess_info.get("status") == "established" and "key" in sess_info:
                            try:
                                dec_e2e_msg_str, e2e_msg_ctr = decrypt_aes_gcm(sess_info["key"], enc_content_b64)
                                if dec_e2e_msg_str is not None:
                                    exp_recv_ctr = sess_info["recv_counter"]
                                    if e2e_msg_ctr == exp_recv_ctr: print(f"\n{color_text('[E2EE DM]', TermColors.OKCYAN)} {color_text(from_user, TermColors.OKGREEN)}{TermColors.BOLD}:{TermColors.ENDC} {dec_e2e_msg_str}"); sess_info["recv_counter"] += 1
                                    else: print_system_message(f"E2EE message counter mismatch from '{from_user}'! Expected: {exp_recv_ctr}, Got: {e2e_msg_ctr}", "error")
                                else: print_system_message(f"Failed to decrypt E2EE message from '{from_user}'.", "error")
                            except Exception as e: print_system_message(f"Error processing E2E_DM_MESSAGE from '{from_user}': {e}", "error"); traceback.print_exc()
                        else: print_system_message(f"Received E2EE DM from '{from_user}', but no active/valid session key.", "warning")
                elif command in ["SERVER_ERROR", "SERVER_RESPONSE"]: print_system_message(f"{payload.get('error', payload.get('message', 'Unknown server response'))}", "warning")
                else: print_system_message(f"Unknown command from server: {command}, Payload: {payload}", "warning")
    except ConnectionResetError: print_system_message("Connection closed by server.", "warning"); e2e_key_registered_this_session = False
    except BrokenPipeError: print_system_message("Connection to server broken (Broken Pipe).", "warning"); e2e_key_registered_this_session = False
    except Exception as e: print_system_message(f"Error in receive_messages: {e}", "error"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        print_system_message("Connection closed. Press Enter to exit.", "info"); e2e_key_registered_this_session = False

def perform_dh_key_exchange(sock):
    global session_key, outgoing_message_counter_to_server, expected_incoming_message_counter_from_server
    if not server_signing_public_key: print_system_message("Server verification key not loaded.", "error"); return False
    try:
        dh_init_data = sock.recv(4096).strip(); parts = dh_init_data.split(b":")
        if len(parts) != 3 or parts[0] != b"DH_INIT_SERVER_PUBKEY": print_system_message("Invalid DH init format from server.", "error"); return False
        serv_dh_pub_bytes = base64.b64decode(parts[1]); sig_bytes = base64.b64decode(parts[2])
        if not verify_signature(server_signing_public_key, sig_bytes, serv_dh_pub_bytes): print_system_message("Server signature VERIFICATION FAILED!", "error"); return False
        print_system_message("Server signature verified.", "success")
        cli_dh_priv, cli_dh_pub = generate_dh_keys(); cli_dh_pub_bytes = serialize_public_key(cli_dh_pub)
        sock.sendall(b"DH_CLIENT_PUBKEY:" + base64.b64encode(cli_dh_pub_bytes) + b"\n")
        print_system_message("Client DH public key sent.", "info")
        session_key = derive_shared_key(cli_dh_priv, serv_dh_pub_bytes); print_system_message(f"Session key with server derived.", "info")
        if sock.recv(1024).strip() == b"DH_SUCCESS":
            print_system_message("DH success confirmation received from server.", "success")
            outgoing_message_counter_to_server = 0; expected_incoming_message_counter_from_server = 0
            return True
        else: print_system_message(f"DH confirmation not received.", "error"); session_key = None; return False
    except Exception as e: print_system_message(f"Error during DH key exchange: {e}", "error"); traceback.print_exc(); session_key = None; return False

def handle_dm_command(recipient_username, message_content):
    global active_e2e_dm_sessions
    if not my_e2e_identity_private_key: print_system_message("Personal E2EE identity key not loaded. Cannot send DM.", "error"); return
    session_info = active_e2e_dm_sessions.get(recipient_username)
    if session_info and session_info.get("status") == "established" and "key" in session_info:
        print_system_message(f"Sending E2EE message to '{recipient_username}' via existing session...", "info")
        current_e2e_send_counter = session_info["send_counter"]
        encrypted_e2e_message_b64 = encrypt_aes_gcm(session_info["key"], message_content, current_e2e_send_counter)
        session_info["send_counter"] = current_e2e_send_counter + 1
        e2e_message_payload = {"to": recipient_username, "e2e_encrypted_content_b64": encrypted_e2e_message_b64}
        if send_secure_command(client_socket, "E2E_DM_MESSAGE", e2e_message_payload): print_system_message(f"E2EE message sent to '{recipient_username}'.", "info")
        else: print_system_message(f"Failed to send E2EE message to '{recipient_username}'.", "error"); session_info["send_counter"] = current_e2e_send_counter
        return
    if session_info and session_info.get("status") == "initiating_dh":
        print_system_message(f"E2EE DH exchange with '{recipient_username}' already in progress. Waiting for response.", "info")
        session_info["initial_message_to_send"] = message_content; print_system_message(f"Your message will be sent after DH completion: {message_content[:20]}...", "info"); return
    print_system_message(f"Initiating new E2EE DH session with '{recipient_username}'...", "info")
    peer_identity_pub_key_pem = request_e2e_identity_public_key_and_wait(recipient_username)
    if not peer_identity_pub_key_pem: print_system_message(f"Failed to get identity key for '{recipient_username}'. Cannot send DM.", "error"); active_e2e_dm_sessions.pop(recipient_username, None); return
    try: _ = load_signing_public_key_from_pem(peer_identity_pub_key_pem)
    except Exception as e: print_system_message(f"Identity key for '{recipient_username}' is invalid: {e}", "error"); active_e2e_dm_sessions.pop(recipient_username, None); return
    my_ephemeral_dh_priv, my_ephemeral_dh_pub = generate_dh_keys(); my_ephemeral_dh_pub_bytes = serialize_public_key(my_ephemeral_dh_pub)
    signature_on_my_eph_dh = sign_data(my_e2e_identity_private_key, my_ephemeral_dh_pub_bytes)
    initiate_payload = {"to": recipient_username, "ephemeral_dh_pub_key_b64": base64.b64encode(my_ephemeral_dh_pub_bytes).decode(), "signature_b64": base64.b64encode(signature_on_my_eph_dh).decode()}
    active_e2e_dm_sessions[recipient_username] = {"status": "initiating_dh", "dh_ephemeral_priv_key": my_ephemeral_dh_priv, "peer_e2e_identity_pub_key_pem": peer_identity_pub_key_pem, "initial_message_to_send": message_content}
    if send_secure_command(client_socket, "E2E_DH_INITIATE", initiate_payload): print_system_message(f"E2EE DH initiation request sent to '{recipient_username}'. Waiting for response...", "info")
    else: print_system_message(f"Failed to send E2EE DH initiation request to '{recipient_username}'.", "error"); active_e2e_dm_sessions.pop(recipient_username, None)

def display_prompt():
    if is_authenticated and username_cache: return f"{color_text(username_cache, TermColors.OKCYAN)}{TermColors.BOLD}:{TermColors.ENDC} "
    else: return color_text("Login/Register/Exit ('signin', 'signup', 'exit'): ", TermColors.WARNING)

def main():
    global client_socket, is_authenticated, username_cache, e2e_key_registered_this_session
    print_system_message("Secure Chat Client Initializing...", "header")
    if not load_server_verification_key(): print_system_message("Client initialization failed.", "error"); return
    if not load_or_generate_my_e2e_identity_keys(): print_system_message("Client initialization failed.", "error"); return
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT)); print_system_message(f"Connected to server at {HOST}:{PORT}.", "success")
        if not perform_dh_key_exchange(client_socket): print_system_message("Key exchange/Server auth failed. Exiting.", "error"); client_socket.close(); return
        threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()
        print_system_message("Type 'help' for available commands.", "info")
        while True:
            current_prompt = display_prompt()
            try: user_input = input(current_prompt).strip()
            except EOFError: print_system_message("EOF received, exiting...", "warning"); break
            except KeyboardInterrupt: print_system_message("\nKeyboardInterrupt received, exiting...", "warning"); break
            if not is_authenticated:
                action = user_input.lower()
                if action == "exit": break
                elif action == "signup":
                    uname=input(f"{color_text('? Signup - Username:', TermColors.OKBLUE)} "); passwd=getpass.getpass(f"{color_text('? Signup - Password:', TermColors.OKBLUE)} "); cpasswd=getpass.getpass(f"{color_text('? Signup - Confirm Password:', TermColors.OKBLUE)} ")
                    if not uname or not passwd: print_system_message("Username or password cannot be empty.", "error"); continue
                    if passwd != cpasswd: print_system_message("Passwords do not match.", "error"); continue
                    if send_secure_command(client_socket, "SECURE_SIGNUP", {"username":uname, "password":passwd}): username_cache=uname; time.sleep(0.3); 
                elif action == "signin":
                    uname=input(f"{color_text('? Login - Username:', TermColors.OKBLUE)} "); passwd=getpass.getpass(f"{color_text('? Login - Password:', TermColors.OKBLUE)} ")
                    if not uname or not passwd: print_system_message("Username or password cannot be empty.", "error"); continue
                    if send_secure_command(client_socket, "SECURE_SIGNIN", {"username":uname, "password":passwd}): username_cache=uname; time.sleep(0.3); 
                elif action == "help": print_system_message("Commands (not logged in): 'signin', 'signup', 'exit'", "info")
                elif action: print_system_message(f"Invalid command: {action}. Type 'help'.", "error")
            else: 
                if user_input.lower() == "exit": break
                if user_input.lower() == "logout": 
                    is_authenticated=False; username_cache=None; active_e2e_dm_sessions.clear(); received_e2e_identity_public_keys_cache.clear()
                    e2e_key_registered_this_session = False; e2e_pubkey_requests.clear(); print_system_message("Logged out successfully.", "success"); continue
                parts = user_input.split(" ", 2); cmd = parts[0].lower()
                if cmd == "broadcast" and len(parts) >= 2: send_secure_command(client_socket, "BROADCAST", {"content": " ".join(parts[1:])})
                elif cmd == "dm" and len(parts) == 3: handle_dm_command(parts[1], parts[2])
                elif cmd == "help": print_system_message("Commands: 'broadcast <message>', 'dm <user> <message>', 'logout', 'exit'", "info")
                elif user_input: print_system_message(f"Invalid command: {cmd}. Type 'help'.", "error")
    except ConnectionRefusedError: print_system_message(f"Connection refused by server at {HOST}:{PORT}.", "error")
    except Exception as e: print_system_message(f"Main client loop error: {e}", "error"); traceback.print_exc()
    finally:
        if client_socket: 
            try: client_socket.close()
            except: pass
        e2e_key_registered_this_session = False
        print_system_message("Client terminated.", "info")

if __name__ == "__main__":
    main()