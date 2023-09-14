import bcrypt
import re

usuarios = []

EMAIL_ADMIN = "juan.nacif2002@gmail.com"
SENHA_HASHED_ADMIN = bcrypt.hashpw("senha123".encode('utf-8'), bcrypt.gensalt())

def criar_hash_senha(senha):
    return bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

def verificar_senha(senha, senha_hashed):
    return bcrypt.checkpw(senha.encode('utf-8'), senha_hashed)

def email_eh_valido(email):
    return re.match(r"^[a-zA-Z0-9._%+-]{4,}@gmail\.com$", email)

def registrar_usuario():
    email = input("Digite seu email: ")
    
    if not email_eh_valido(email):
        print("Email inválido. Precisa ter mínimo de 4 caracteres antes de '@gmail.com'.")
        return

    if any(usuario['email'] == email for usuario in usuarios):
        print("Email já cadastrado!")
        return

    senha = input("Digite uma senha (mínimo de 6 caracteres): ")
    
    if len(senha) < 6:
        print("Senha curta. Mínimo de 6 caracteres.")
        return

    usuarios.append({'email': email, 'password': criar_hash_senha(senha)})
    print("Usuário cadastrado!")

def fazer_login():
    email = input("Digite seu email: ")
    senha = input("Digite sua senha: ")

    usuario = next((usuario for usuario in usuarios if usuario['email'] == email), None)
    if usuario and verificar_senha(senha, usuario['password']):
        print("Login bem-sucedido!")
    else:
        print("Email ou senha incorretos.")

def login_admin():
    email = input("Email do administrador: ")
    senha = input("Senha do administrador: ")

    if email == EMAIL_ADMIN and verificar_senha(senha, SENHA_HASHED_ADMIN):
        for usuario in usuarios:
            print(f"Email: {usuario['email']} | Hashed Password: {usuario['password'].decode('utf-8')}")
    else:
        print("Credenciais de administrador inválidas.")

def principal():
    while True:
        print(f'''Bem vindo ao Login Seguro do Juan Nacif
Fique tranquilo, seus dados serão criptografados e amazernados
        
[ 1 ] Cadastre-se
[ 2 ] Entrar
[ 3 ] Login de administrador
[ 4 ] Sair''')
        opcao = input("Opção: ")

        if opcao == "1":
            registrar_usuario()
        elif opcao == "2":
            fazer_login()
        elif opcao == "3":
            login_admin()
        elif opcao == "4":
            break
        else:
            print("Opção inválida.")

if __name__ == "__main__":
    principal()