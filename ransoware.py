import os
import tkinter as tk
from tkinter import filedialog as fd, messagebox as mb, Label as L, Button as B, Frame as F, simpledialog as sd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes as grb

def encrypt_file(file, key):
    try:
        with open(file, 'rb') as f:
            data = f.read()

        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(data)

        with open(file, 'wb') as ef:
            [ef.write(x) for x in (cipher.nonce, tag, ct)]

        return True
    except Exception as e:
        mb.showerror("Erro", f"Erro ao criptografar {file}: {str(e)}")
        return False

def decrypt_file(file, key):
    try:
        with open(file, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(file, 'wb') as df:
            df.write(data)

        return True
    except Exception as e:
        mb.showerror("Erro", f"Erro ao decifrar {file}: {str(e)}")
        return False

def encrypt_directory(directory, key, level):
    try:
        num_files = 0
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                if encrypt_file(file_path, key):
                    num_files += 1
                else:
                    return
        show_encryption_report(directory, len(key), num_files)
    except Exception as e:
        mb.showerror("Erro", f"Erro ao criptografar diretório {directory}: {str(e)}")

def decrypt_directory(directory, key):
    try:
        num_files = 0
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                if decrypt_file(file_path, key):
                    num_files += 1
                else:
                    return
        mb.showinfo("Sucesso", f"Arquivos decifrados com sucesso em {directory}")
    except Exception as e:
        mb.showerror("Erro", f"Erro ao decifrar diretório {directory}: {str(e)}")

def show_encryption_report(directory, key_length, num_files):
    report = f"Relatório de Criptografia:\n\nDiretório: {directory}\nComprimento da Chave: {key_length * 8} bits\nNúmero de Arquivos Criptografados: {num_files}"
    mb.showinfo("Relatório de Criptografia", report)

def select_directory_to_encrypt():
    directory = fd.askdirectory()
    if directory:
        level = sd.askstring("Nível de Dificuldade", "Escolha o nível de dificuldade (fácil, médio, difícil):").lower()
        if level not in ["fácil", "médio", "difícil"]:
            mb.showwarning("Entrada Inválida", "Nível de dificuldade inválido. Usando o nível fácil como padrão.")
            level = "fácil"
        key_length = 16 if level == "fácil" else 24 if level == "médio" else 32
        key = grb(key_length)
        encrypt_directory(directory, key, level)
        with open("encryption_key.bin", "wb") as key_file:
            key_file.write(key)

def select_directory_to_decrypt():
    directory = fd.askdirectory()
    if directory:
        key_file = fd.askopenfilename(title="Selecione o arquivo de chave", filetypes=[("Bin files", "*.bin")])
        if key_file:
            with open(key_file, "rb") as kf:
                key = kf.read()
                decrypt_directory(directory, key)

def show_prevention_tips():
    tips = "Prevenção de Ransomware:\n\n1. Mantenha seu software atualizado.\n2. Faça backup regularmente dos seus arquivos.\n3. Tenha cuidado ao clicar em links ou baixar anexos de e-mails não solicitados."
    mb.showinfo("Dicas de Prevenção", tips)

root = tk.Tk()
root.title("Simulador de Ransomware")
root.config(bg="black")

f = F(root, bg="black", padx=20, pady=20)
f.pack()

l = L(f, text="Simulador de Ransomware", font=("Helvetica", 16), bg="black", fg="red")
l.pack(pady=10)

b1 = B(f, text="Criptografar Pasta", command=select_directory_to_encrypt, padx=10, pady=5, bg="black", activebackground="black", fg="red")
b1.pack(pady=10)

b2 = B(f, text="Decifrar Pasta", command=select_directory_to_decrypt, padx=10, pady=5, bg="black", activebackground="black", fg="red")
b2.pack(pady=10)

b3 = B(f, text="Dicas de Prevenção", command=show_prevention_tips, padx=10, pady=5, bg="black", activebackground="black", fg="red")
b3.pack(pady=10)

root.mainloop()
