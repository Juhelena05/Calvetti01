from cryptography.fernet import Fernet

# Gerar uma chave simétrica
def gerar_chave():
    chave = Fernet.generate_key()
    with open("chave.key", "wb") as chave_arquivo:
        chave_arquivo.write(chave)

# Carregar a chave simétrica
def carregar_chave():
    with open("chave.key", "rb") as chave_arquivo:
        return chave_arquivo.read()

# Criptografar uma mensagem
def criptografar(mensagem):
    chave = carregar_chave()
    fernet = Fernet(chave)
    mensagem_criptografada = fernet.encrypt(mensagem.encode())
    return mensagem_criptografada

# Descriptografar uma mensagem
def descriptografar(mensagem_criptografada):
    chave = carregar_chave()
    fernet = Fernet(chave)
    mensagem_descriptografada = fernet.decrypt(mensagem_criptografada).decode()
    return mensagem_descriptografada

# Exemplo de uso
if __name__ == "__main__":
    gerar_chave()  # Gera e salva a chave em um arquivo

    mensagem = "Esta é uma mensagem secreta."
    print("Mensagem original:", mensagem)

    mensagem_criptografada = criptografar(mensagem)
    print("Mensagem criptografada:", mensagem_criptografada)

    mensagem_descriptografada = descriptografar(mensagem_criptografada)
    print("Mensagem descriptografada:", mensagem_descriptografada)