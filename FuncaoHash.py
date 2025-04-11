import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Arquivos de chave
ARQUIVO_PRIVADA = "chave_privada.pem"
ARQUIVO_PUBLICA = "chave_publica.pem"
SENHA_CHAVE = b"senha_top"

# === Gerar e salvar chaves RSA com criptografia ===
def gerar_chaves():
    if os.path.exists(ARQUIVO_PRIVADA) or os.path.exists(ARQUIVO_PUBLICA):
        print("As chaves já existem.")
        return

    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Salva a chave privada com senha
    with open(ARQUIVO_PRIVADA, "wb") as f:
        f.write(
            chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(SENHA_CHAVE)
            )
        )

    # Salva a chave pública
    chave_publica = chave_privada.public_key()
    with open(ARQUIVO_PUBLICA, "wb") as f:
        f.write(
            chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("✅ Chaves RSA geradas com sucesso.")

# === Funções para carregar chaves ===
def carregar_chave_privada():
    with open(ARQUIVO_PRIVADA, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=SENHA_CHAVE, backend=default_backend())

def carregar_chave_publica():
    with open(ARQUIVO_PUBLICA, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

# === Gerar hash SHA-256 ===
def gerar_hash(mensagem: str) -> bytes:
    return hashlib.sha256(mensagem.encode()).digest()

# === Assinar hash com chave privada RSA ===
def assinar_hash(hash_bytes: bytes) -> bytes:
    chave_privada = carregar_chave_privada()
    assinatura = chave_privada.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return assinatura

# === Verificar assinatura com chave pública RSA ===
def verificar_assinatura(hash_bytes: bytes, assinatura: bytes) -> bool:
    chave_publica = carregar_chave_publica()
    try:
        chave_publica.verify(
            assinatura,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# === Exemplo de uso ===
if __name__ == "__main__":
    gerar_chaves()

    mensagem = "Essa é uma mensagem ultra confidencial."

    print("\n📩 Mensagem:", mensagem)

    hash_msg = gerar_hash(mensagem)
    print("🔑 Hash da mensagem (SHA-256):", hash_msg.hex())

    assinatura = assinar_hash(hash_msg)
    print("🖋️ Assinatura digital (bytes):", assinatura.hex())

    # Verificação
    if verificar_assinatura(hash_msg, assinatura):
        print("✅ Assinatura verificada com sucesso.")
    else:
        print("❌ Assinatura inválida.")
