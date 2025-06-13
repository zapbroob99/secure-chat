import os
import base64
import hashlib
import struct # Sayaçları baytlara dönüştürmek için
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding, utils # utils eklendi
from cryptography.hazmat.backends import default_backend
import hmac as std_hmac

P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
G = 2
DH_PARAMETERS = dh.DHParameterNumbers(P, G).parameters(default_backend())

# --- Diffie-Hellman Fonksiyonları ---
def generate_dh_keys():
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key): # DH Genel Anahtarı için
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = serialization.load_der_public_key(
        peer_public_key_bytes,
        backend=default_backend()
    )
    if not isinstance(peer_public_key, dh.DHPublicKey):
        raise TypeError(f"Beklenmedik anahtar türü: {type(peer_public_key)}. DHPublicKey bekleniyordu.")
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'aes session key',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

# --- Parola Karma Fonksiyonları ---
def hash_password(password):
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    stored_value = base64.b64encode(salt + pwd_hash).decode('utf-8')
    return stored_value

def verify_password(stored_password_b64, provided_password):
    try:
        decoded_stored_password = base64.b64decode(stored_password_b64)
        salt = decoded_stored_password[:16]
        stored_hash_from_db = decoded_stored_password[16:]
        recalculated_hash = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        return std_hmac.compare_digest(recalculated_hash, stored_hash_from_db)
    except Exception:
        return False

# --- Sunucu/Kullanıcı İmzalama/E2EE Anahtar Fonksiyonları (RSA ile) ---
def generate_signing_keys(): # RSA anahtar çifti üretir (imzalama veya E2EE için)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, 
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(signing_private_key, data): # Veriyi imzalar
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    signature = signing_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(signing_public_key, signature, data): # İmzayı doğrular
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    try:
        signing_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception: 
        return False

def serialize_signing_public_key_pem(public_key): 
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_signing_public_key_from_pem(pem_bytes): 
    if isinstance(pem_bytes, str): # Eğer string gelirse byte'a çevir
        pem_bytes = pem_bytes.encode('utf-8')
    return serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )

def serialize_signing_private_key_pem(private_key, password=None): 
    encryption_algo = serialization.BestAvailableEncryption(password.encode('utf-8')) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )

def load_signing_private_key_from_pem(pem_bytes, password=None): 
    if isinstance(pem_bytes, str): # Eğer string gelirse byte'a çevir
        pem_bytes = pem_bytes.encode('utf-8')
    return serialization.load_pem_private_key(
        pem_bytes,
        password=password.encode('utf-8') if password else None,
        backend=default_backend()
    )

# --- AES-GCM Şifreleme Fonksiyonları (Sıralı Nonce ile) ---
NONCE_RANDOM_PART_LEN = 8
NONCE_COUNTER_PART_LEN = 4 
NONCE_LEN = NONCE_RANDOM_PART_LEN + NONCE_COUNTER_PART_LEN

def encrypt_aes_gcm(key, plaintext, message_counter):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    random_part = os.urandom(NONCE_RANDOM_PART_LEN)
    counter_part = struct.pack('>I', message_counter)
    if len(counter_part) > NONCE_COUNTER_PART_LEN:
        raise ValueError("Mesaj sayacı çok büyük.")
    counter_part = counter_part.rjust(NONCE_COUNTER_PART_LEN, b'\x00')
    nonce = random_part + counter_part
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"Nonce uzunluğu hatalı: {len(nonce)}")
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(nonce + encryptor.tag + ciphertext).decode('utf-8')

def decrypt_aes_gcm(key, encrypted_blob_b64):
    try:
        encrypted_blob = base64.b64decode(encrypted_blob_b64)
        nonce = encrypted_blob[:NONCE_LEN]
        tag = encrypted_blob[NONCE_LEN : NONCE_LEN + 16]
        ciphertext = encrypted_blob[NONCE_LEN + 16:]
        counter_part = nonce[NONCE_RANDOM_PART_LEN:]
        message_counter = struct.unpack('>I', counter_part)[0]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext_bytes.decode('utf-8'), message_counter
    except Exception:
        return None, -1

# --- RSA Şifreleme/Deşifreleme Fonksiyonları (E2EE DM Anahtarı için) ---
def encrypt_with_rsa_public_key(public_key_obj, data_to_encrypt):
    if not isinstance(data_to_encrypt, bytes):
        data_to_encrypt = data_to_encrypt.encode('utf-8')
    ciphertext = public_key_obj.encrypt(
        data_to_encrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_rsa_private_key(private_key_obj, ciphertext_to_decrypt):
    plaintext = private_key_obj.decrypt(
        ciphertext_to_decrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# --- Yeni Simetrik Anahtar Üretme Fonksiyonu ---
def generate_symmetric_key(length=32):
    return os.urandom(length)


if __name__ == '__main__':
   
    data_to_sign_str = "Bu veri sunucu tarafından imzalanacak." 
    data_to_sign_bytes = data_to_sign_str.encode('utf-8') 

    print("\nRSA Şifreleme/Deşifreleme Testi Başlıyor...")
    recipient_priv_key, recipient_pub_key = generate_signing_keys()
    symmetric_dm_key = generate_symmetric_key()
    print(f"Şifrelenecek simetrik DM anahtarı (hex): {symmetric_dm_key.hex()}")
    encrypted_dm_key = encrypt_with_rsa_public_key(recipient_pub_key, symmetric_dm_key)
    print(f"Şifrelenmiş DM anahtarı (b64): {base64.b64encode(encrypted_dm_key).decode()}")
    decrypted_dm_key = decrypt_with_rsa_private_key(recipient_priv_key, encrypted_dm_key)
    print(f"Deşifre edilmiş simetrik DM anahtarı (hex): {decrypted_dm_key.hex()}")
    assert symmetric_dm_key == decrypted_dm_key
    print("RSA Şifreleme/Deşifreleme Testi Başarılı!")