# Author: Danu Pratama 
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time

class AESEncryptor:  # Kelas untuk enkripsi dan dekripsi menggunakan AES
    def __init__(self, key):
        self.key = key.encode()  # Mengkode kunci ke dalam bytes

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC)  # Buat cipher baru untuk setiap enkripsi
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ciphertext  # Kembalikan IV yang digabungkan dengan ciphertext

    def decrypt(self, iv, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

class FileEncryptor:  # Kelas untuk menangani proses enkripsi dan dekripsi file
    def __init__(self, entry_file, entry_key, label_result):
        self.entry_file = entry_file
        self.entry_key = entry_key
        self.label_result = label_result
        self.file_handler = None
        self.timer = Timer()  # Timer untuk menghitung waktu proses

    def browse_file(self):  # Membuka dialog untuk memilih file
        filename = filedialog.askopenfilename(initialdir="/", title="Pilih file", filetypes=(("All files", "*.*"),))
        self.entry_file.delete(0, tk.END)
        self.entry_file.insert(0, filename)

    def get_file_type(self, filename):  # Mendapatkan tipe file berdasarkan ekstensi
        return FileHandler.get_file_type(filename)

    def encrypt_file(self):  # Proses enkripsi file
        filename = self.entry_file.get()
        key = self.entry_key.get()

        self.file_handler = FileHandler(filename, key)

        if not filename:
            messagebox.showerror("Error", "Masukkan file terlebih dahulu")
            return

        if not self.file_handler.validate_key():
            messagebox.showerror("Error", "Panjang kunci harus 16, 24, atau 32 karakter")
            return

        try:
            self.timer.start()
            plaintext = self.file_handler.read_file()

            aes_cipher = AESEncryptor(key)  # Inisialisasi AESEncryptor
            encrypted_data = aes_cipher.encrypt(plaintext)  # Enkripsi data

            output_filename = filename + ".encrypted"
            self.file_handler.filename = output_filename
            self.file_handler.write_file(encrypted_data)

            self.timer.stop()
            elapsed_time = self.timer.elapsed_time()
            file_type = self.get_file_type(filename)

            self.label_result.config(text=f"Status: Berhasil Enkripsi | Waktu Proses: {elapsed_time:.2f} detik | Tipe: {file_type}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):  # Proses dekripsi file
        filename = self.entry_file.get()
        key = self.entry_key.get()

        self.file_handler = FileHandler(filename, key)

        if not filename:
            messagebox.showerror("Error", "Masukkan file terlebih dahulu")
            return

        if not self.file_handler.validate_key():
            messagebox.showerror("Error", "Panjang kunci harus 16, 24, atau 32 karakter")
            return

        if not filename.endswith(".encrypted"):
            messagebox.showerror("Error", "File yang dipilih bukan file terenkripsi (.encrypted)")
            return

        try:
            self.timer.start()
            iv_and_ciphertext = self.file_handler.read_file()
            iv = iv_and_ciphertext[:16]
            ciphertext = iv_and_ciphertext[16:]

            aes_cipher = AESEncryptor(key)  # Inisialisasi AESEncryptor
            plaintext = aes_cipher.decrypt(iv, ciphertext)  # Dekripsi data

            output_filename = filename[:-10]
            self.file_handler.filename = output_filename
            self.file_handler.write_file(plaintext)

            self.timer.stop()
            elapsed_time = self.timer.elapsed_time()
            file_type = self.get_file_type(output_filename)

            self.label_result.config(text=f"Status: Berhasil Dekripsi | Waktu Proses: {elapsed_time:.2f} detik | Tipe: {file_type}")
        except ValueError as e:
            messagebox.showerror("Error", "Dekripsi gagal: Kunci salah atau file rusak")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def refresh(self):  # Mengatur ulang input dan status
        self.entry_file.delete(0, tk.END)
        self.entry_key.delete(0, tk.END)
        self.label_result.config(text="Status: - | Waktu Proses: - | Tipe: -")

class FileHandler:  # Kelas untuk membaca dan menulis file
    def __init__(self, filename='', key=''):
        self.filename = filename
        self.key = key

    def read_file(self):  # Membaca isi file
        with open(self.filename, "rb") as f:
            return f.read()

    def write_file(self, data):  # Menulis data ke file
        with open(self.filename, "wb") as f:
            f.write(data)

    def validate_key(self):  # Memvalidasi panjang kunci
        return len(self.key) in (16, 24, 32)

    @staticmethod
    def get_file_type(filename):  # Mendapatkan tipe file berdasarkan ekstensi
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
            return "Gambar"
        elif ext in ['.pdf']:
            return "PDF"
        elif ext in ['.doc', '.docx']:
            return "Word"
        elif ext in ['.xlsx', '.xls']:
            return "Excel"
        elif ext in ['.ppt', '.pptx']:
            return "PowerPoint"
        elif ext in ['.mp4', '.avi', '.mov', '.mkv', '.flv']:
            return "Video"
        elif ext in ['.txt']:
            return "Teks"
        else:
            return "Tak dikenal"

class Timer:  # Kelas untuk menghitung waktu
    def __init__(self):
        self.start_time = 0
        self.end_time = 0

    def start(self):  # Memulai timer
        self.start_time = time.time()

    def stop(self):  # Menghentikan timer
        self.end_time = time.time()

    def elapsed_time(self):  # Menghitung waktu yang telah berlalu
        return self.end_time - self.start_time

# Kelas Tk untuk menginisialisasi jendela aplikasi
class Tk(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Tambahkan atribut di sini, misalnya:
        self.configure(bg="#ededed")  # Mengatur warna latar belakang

# Kelas TTk untuk memperluas Frame dari ttk
class TTk(ttk.Frame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Tambahkan atribut di sini, misalnya:
        self.configure(bg="#ededed")  # Mengatur warna latar belakang

class App:  # Kelas utama untuk aplikasi
    def __init__(self, root):
        self.root = root
        self.root.title("FileGuard - Danu Pratama - Enkripsi dan Dekripsi File")
        self.root.geometry("420x560")
        self.root.configure(bg="#ededed")

        # Membuat instance FileEncryptor
        self.entry_file = ttk.Entry(root, width=50, font=("Arial", 12))
        self.entry_key = ttk.Entry(root, width=50, font=("Arial", 12))
        self.label_result = tk.Label(root, text="Status: - | Waktu Proses: - | Tipe: -", font=("Arial", 11, "bold"), bg="#ededed", fg="black")
        self.file_encryptor = FileEncryptor(self.entry_file, self.entry_key, self.label_result)

        # Membuat komponen GUI
        self.create_widgets()

    def create_widgets(self):  # Membuat dan menata komponen GUI
        label_file = tk.Label(self.root, text="Advanced Encryption Standard", font=("Arial", 15), bg="#ededed", fg="#000000")
        label_file.pack(pady=30)

        self.entry_file.pack(padx=20, pady=10, ipady=5)

        button_browse = tk.Button(self.root, text="Upload File", command=self.file_encryptor.browse_file, bg="yellow", fg="black", width=15, font=("Arial", 11, "bold"))
        button_browse.pack(pady=30)

        label_key = tk.Label(self.root, text="Kunci Rahasia*", font=("Arial", 12, "bold"), bg="#ededed", fg="#000000")
        label_key.pack(pady=20)

        self.entry_key.pack(padx=20, pady=10, ipady=5)

        # Frame untuk tombol-tombol
        button_frame = tk.Frame(self.root, bg="#ededed")
        button_frame.pack(pady=20)

        button_encrypt = tk.Button(button_frame, text="Enkripsi", command=self.file_encryptor.encrypt_file, bg="blue", fg="white", width=10, font=("Arial", 11, "bold"))
        button_encrypt.pack(side=tk.LEFT, padx=15)

        button_decrypt = tk.Button(button_frame, text="Dekripsi", command=self.file_encryptor.decrypt_file, bg="green", fg="white", width=10, font=("Arial", 11, "bold"))
        button_decrypt.pack(side=tk.LEFT, padx=15)

        button_refresh = tk.Button(button_frame, text="Refresh", command=self.file_encryptor.refresh, bg="red", fg="white", width=10, font=("Arial", 11, "bold"))
        button_refresh.pack(side=tk.LEFT, padx=15)

        self.label_result.pack(pady=30)


if __name__ == "__main__":
    root = Tk()
    app = App(root)
    root.mainloop()
