import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Caminhos padrão dos arquivos de chave
ARQUIVO_PRIVADA = "chave_privada.pem"
ARQUIVO_PUBLICA = "chave_publica.pem"
SENHA_CHAVE_PRIVADA = b"minha_senha_super_secreta"

# Gera um novo par de chaves RSA (2048 bits) e salva nos arquivos
def gerar_chaves():
    if os.path.exists(ARQUIVO_PRIVADA) or os.path.exists(ARQUIVO_PUBLICA):
        print("As chaves já existem. Apague os arquivos para gerar novos.")
        return

    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    chave_publica = chave_privada.public_key()

    # Salva a chave privada com criptografia (proteção por senha)
    with open(ARQUIVO_PRIVADA, "wb") as priv_file:
        priv_file.write(
            chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(SENHA_CHAVE_PRIVADA)
            )
        )

    # Salva a chave pública (sem senha, pois é pública)
    with open(ARQUIVO_PUBLICA, "wb") as pub_file:
        pub_file.write(
            chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("Chaves geradas com sucesso!")

# Carrega a chave pública do arquivo
def carregar_chave_publica():
    try:
        with open(ARQUIVO_PUBLICA, "rb") as pub_file:
            return serialization.load_pem_public_key(pub_file.read(), backend=default_backend())
    except Exception as e:
        print("Erro ao carregar chave pública:", e)

# Carrega a chave privada do arquivo, usando a senha definida
def carregar_chave_privada():
    try:
        with open(ARQUIVO_PRIVADA, "rb") as priv_file:
            return serialization.load_pem_private_key(
                priv_file.read(),
                password=SENHA_CHAVE_PRIVADA,
                backend=default_backend()
            )
    except Exception as e:
        print("Erro ao carregar chave privada:", e)

# Criptografa uma mensagem usando a chave pública
def criptografar(mensagem: str) -> bytes:
    chave_publica = carregar_chave_publica()
    if not chave_publica:
        return b""

    return chave_publica.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Descriptografa uma mensagem criptografada usando a chave privada
def descriptografar(mensagem_criptografada: bytes) -> str:
    chave_privada = carregar_chave_privada()
    if not chave_privada:
        return ""

    return chave_privada.decrypt(
        mensagem_criptografada,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# Exemplo de uso
if __name__ == "__main__":
    gerar_chaves()  # Gera as chaves só se ainda não existirem

    mensagem_original = "Senha do cofre é 123456"
    print("\nMensagem original:", mensagem_original)

    mensagem_criptografada = criptografar(mensagem_original)
    print("\nMensagem criptografada (em bytes):", mensagem_criptografada)

    mensagem_descriptografada = descriptografar(mensagem_criptografada)
    print("\nMensagem descriptografada:", mensagem_descriptografada)
