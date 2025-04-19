import threading  # Untuk menjalankan timer dan menghentikan proses setelah timeout
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
import os

# Flag untuk menghentikan brute force setelah timeout
stop_bruteforce = False

def timeout_handler():
    """Fungsi ini dipanggil saat waktu habis."""
    global stop_bruteforce
    stop_bruteforce = True  # Set flag untuk menghentikan brute force
    print("\nWaktu habis! Proses brute force dihentikan.")

def bruteforce_decrypt(encrypted_file, iv, correct_plaintext_start, timeout=60):
    """
    Fungsi untuk melakukan brute force dekripsi pada file terenkripsi.
    
    Parameters:
        encrypted_file: Nama file terenkripsi yang akan didekripsi.
        iv: Initial vector yang digunakan dalam enkripsi.
        correct_plaintext_start: Sebagian plaintext yang diketahui.
        timeout: Waktu maksimum untuk mencoba kunci dalam detik.
    """
    global stop_bruteforce
    timer = threading.Timer(timeout, timeout_handler)  # Membuat timer untuk timeout
    timer.start()  # Memulai timer

    # Membaca file terenkripsi
    with open(encrypted_file, "rb") as f:
        iv = f.read(16)  # Membaca IV dari file
        ciphertext = f.read()  # Membaca ciphertext

    # Mendapatkan ukuran dokumen
    file_size = os.path.getsize(encrypted_file)  # Ukuran file dalam byte

    key_length = 16  # Panjang kunci dalam byte (128 bit)
    total_keys = 2 ** (key_length * 8)  # Total kemungkinan kunci

    R = 1_000_000  # Laju pencarian kunci per detik
    A = 1  # Faktor penyesuaian untuk kecepatan perangkat keras
    D = 1  # Faktor penyesuaian untuk teknik optimasi

    attempts = 0  # Inisialisasi jumlah percobaan
    start_time = time.time()  # Menghitung waktu mulai

    for i in range(total_keys):  # Loop melalui semua kemungkinan kunci
        if stop_bruteforce:  # Jika waktu habis
            elapsed_time = time.time() - start_time  # Hitung waktu yang telah berlalu
            total_time_seconds = total_keys / (R * A * D)  # Hitung estimasi waktu dalam detik
            total_time_years = total_time_seconds / (60 * 60 * 24 * 365)  # Konversi ke tahun

            print(f"\nProses dihentikan oleh timeout setelah {elapsed_time:.2f} detik.")
            print(f"Percobaan kunci: {attempts}")
            print(f"Estimasi waktu dalam tahun: {total_time_years:.2f} tahun.")
            print(f"Ukuran dokumen: {file_size} byte untuk file: {encrypted_file}")  # Menampilkan ukuran dokumen dan nama file
            timer.cancel()  # Hentikan timer
            return None, None

        key = i.to_bytes(key_length, byteorder='big')  # Membuat kunci dari integer
        print(f"Mencoba kunci: {key.hex().zfill(32)} pada file: {encrypted_file}")  # Menampilkan kunci dan nama file yang sedang dicoba

        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)  # Inisialisasi cipher AES dengan kunci dan IV
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Dekripsi dan hapus padding

            # Jika plaintext yang didekripsi cocok dengan bagian yang diharapkan
            if plaintext.startswith(correct_plaintext_start.encode()):
                print(f"Kunci ditemukan: {key.hex()}")  # Menampilkan kunci yang ditemukan
                print(f"Plaintext: {plaintext}")  # Menampilkan plaintext
                timer.cancel()  # Hentikan timer
                return key, plaintext  # Kembalikan kunci dan plaintext
        except (ValueError, KeyError):
            pass  # Abaikan kesalahan pada dekripsi yang gagal

        attempts += 1  # Tambah jumlah percobaan

    print("Kunci tidak ditemukan dalam rentang yang diberikan.")  # Jika kunci tidak ditemukan
    timer.cancel()  # Hentikan timer
    return None, None  # Kembalikan None jika tidak ditemukan

if __name__ == "__main__":
    encrypted_file = "AES_Encryption_Test.docx.encrypted"  # Nama file terenkripsi
    iv = b'initialvector123'  # Sesuaikan dengan file enkripsi
    correct_plaintext_start = "Ini"  # Sebagian dari plaintext yang diketahui

    bruteforce_decrypt(encrypted_file, iv, correct_plaintext_start)
