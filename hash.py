import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os

class FileHashCalculator:
    def __init__(self, master):
        self.master = master
        master.title("Calculadora de Hash de Arquivos")
        master.geometry("600x400")

        self.file_path = tk.StringVar()
        self.hash_algorithm = tk.StringVar(value="md5")
        self.result = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        # Entrada do caminho do arquivo
        ttk.Label(main_frame, text="Arquivo ou Pasta:").grid(column=0, row=0, sticky=tk.W)
        ttk.Entry(main_frame, width=50, textvariable=self.file_path).grid(column=1, row=0, sticky=(tk.W, tk.E))
        ttk.Button(main_frame, text="Procurar", command=self.browse_file).grid(column=2, row=0, sticky=tk.W)

        # Seleção do algoritmo de hash
        ttk.Label(main_frame, text="Algoritmo de Hash:").grid(column=0, row=1, sticky=tk.W)
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        ttk.Combobox(main_frame, textvariable=self.hash_algorithm, values=algorithms).grid(column=1, row=1, sticky=(tk.W, tk.E))

        # Botão para calcular o hash
        ttk.Button(main_frame, text="Calcular Hash", command=self.calculate_hash).grid(column=1, row=2, sticky=tk.E)

        # Resultado
        ttk.Label(main_frame, text="Resultado:").grid(column=0, row=3, sticky=tk.W)
        ttk.Entry(main_frame, width=70, textvariable=self.result, state='readonly').grid(column=1, row=3, columnspan=2, sticky=(tk.W, tk.E))

        # Configurar o redimensionamento da grade
        for child in main_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)
        main_frame.columnconfigure(1, weight=1)

    def browse_file(self):
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def calculate_hash(self):
        path = self.file_path.get()
        algorithm = self.hash_algorithm.get()

        if not path:
            messagebox.showerror("Erro", "Por favor, selecione um arquivo ou pasta.")
            return

        try:
            if os.path.isfile(path):
                hash_value = self.hash_file(path, algorithm)
            elif os.path.isdir(path):
                hash_value = self.hash_directory(path, algorithm)
            else:
                messagebox.showerror("Erro", "Caminho inválido.")
                return

            self.result.set(hash_value)
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao calcular o hash: {str(e)}")

    def hash_file(self, file_path, algorithm):
        hash_obj = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def hash_directory(self, dir_path, algorithm):
        hash_obj = hashlib.new(algorithm)
        for root, dirs, files in os.walk(dir_path):
            for file in sorted(files):
                file_path = os.path.join(root, file)
                hash_obj.update(self.hash_file(file_path, algorithm).encode())
        return hash_obj.hexdigest()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileHashCalculator(root)
    root.mainloop()
