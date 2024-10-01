import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import base64

class CalculadoraDeHash:
    def __init__(self, master):
        self.master = master
        master.title("Calculadora de Hash de Arquivos")
        master.geometry("700x500")

        self.caminho_arquivo = tk.StringVar()
        self.algoritmo_hash = tk.StringVar(value="md5")
        self.resultado = tk.StringVar()
        self.modo_base64 = tk.BooleanVar()
        self.comparar_hash = tk.StringVar()

        self.criar_widgets()

    def criar_widgets(self):
        frame_principal = ttk.Frame(self.master, padding="10")
        frame_principal.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        ttk.Label(frame_principal, text="Arquivo ou Pasta:").grid(column=0, row=0, sticky=tk.W)
        ttk.Entry(frame_principal, width=50, textvariable=self.caminho_arquivo).grid(column=1, row=0, sticky=(tk.W, tk.E))
        ttk.Button(frame_principal, text="Procurar", command=self.procurar_arquivo).grid(column=2, row=0, sticky=tk.W)

        ttk.Label(frame_principal, text="Algoritmo de Hash:").grid(column=0, row=1, sticky=tk.W)
        algoritmos = ['md5', 'sha1', 'sha256', 'sha512', 'blake2b', 'sha3_256']
        ttk.Combobox(frame_principal, textvariable=self.algoritmo_hash, values=algoritmos).grid(column=1, row=1, sticky=(tk.W, tk.E))

        ttk.Checkbutton(frame_principal, text="Saída em Base64", variable=self.modo_base64).grid(column=1, row=2, sticky=tk.W)

        ttk.Button(frame_principal, text="Calcular Hash", command=self.calcular_hash).grid(column=1, row=3, sticky=tk.E)

        ttk.Label(frame_principal, text="Resultado:").grid(column=0, row=4, sticky=tk.W)
        ttk.Entry(frame_principal, width=70, textvariable=self.resultado, state='readonly').grid(column=1, row=4, columnspan=2, sticky=(tk.W, tk.E))

        ttk.Label(frame_principal, text="Comparar Hash:").grid(column=0, row=5, sticky=tk.W)
        ttk.Entry(frame_principal, width=70, textvariable=self.comparar_hash).grid(column=1, row=5, columnspan=2, sticky=(tk.W, tk.E))
        ttk.Button(frame_principal, text="Comparar", command=self.comparar_hashes).grid(column=2, row=5, sticky=tk.E)

        for child in frame_principal.winfo_children():
            child.grid_configure(padx=5, pady=5)
        frame_principal.columnconfigure(1, weight=1)

    def procurar_arquivo(self):
        caminho = filedialog.askdirectory() or filedialog.askopenfilename()
        if caminho:
            self.caminho_arquivo.set(caminho)

    def calcular_hash(self):
        caminho = self.caminho_arquivo.get()
        algoritmo = self.algoritmo_hash.get()

        if not caminho:
            messagebox.showerror("Erro", "Por favor, selecione um arquivo ou pasta.")
            return

        try:
            if os.path.isfile(caminho):
                hash_valor = self.hash_arquivo(caminho, algoritmo)
            elif os.path.isdir(caminho):
                hash_valor = self.hash_diretorio(caminho, algoritmo)
            else:
                messagebox.showerror("Erro", "Caminho inválido.")
                return

            if self.modo_base64.get():
                hash_valor = base64.b64encode(bytes.fromhex(hash_valor)).decode()

            self.resultado.set(hash_valor)
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao calcular o hash: {str(e)}")

    def hash_arquivo(self, caminho_arquivo, algoritmo):
        hash_obj = hashlib.new(algoritmo)
        with open(caminho_arquivo, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def hash_diretorio(self, caminho_dir, algoritmo):
        hash_obj = hashlib.new(algoritmo)
        for raiz, dirs, arquivos in os.walk(caminho_dir):
            for arquivo in sorted(arquivos):
                caminho_arquivo = os.path.join(raiz, arquivo)
                hash_obj.update(self.hash_arquivo(caminho_arquivo, algoritmo).encode())
        return hash_obj.hexdigest()

    def comparar_hashes(self):
        hash_calculado = self.resultado.get()
        hash_comparar = self.comparar_hash.get()

        if not hash_calculado:
            messagebox.showerror("Erro", "Por favor, calcule um hash primeiro.")
            return

        if not hash_comparar:
            messagebox.showerror("Erro", "Por favor, insira um hash para comparar.")
            return

        if hash_calculado.lower() == hash_comparar.lower():
            messagebox.showinfo("Resultado", "Os hashes são idênticos!")
        else:
            messagebox.showwarning("Resultado", "Os hashes são diferentes.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CalculadoraDeHash(root)
    root.mainloop()
