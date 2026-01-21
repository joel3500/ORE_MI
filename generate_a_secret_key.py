# fonction a rouler seul sur pour me generer
import secrets;

def gere_moi_une_flash_secret_cle():
    print(secrets.token_hex(32))

gere_moi_une_flash_secret_cle()