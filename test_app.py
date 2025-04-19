import unittest
import time
from unittest.mock import MagicMock, patch
from tkinter import filedialog, messagebox
from AdvancedEncryptionStandard import AESEncryptor, FileEncryptor, FileHandler, Timer

class TestAESEncryptor(unittest.TestCase):

    def setUp(self):
        self.key = 'thisisasecretkey'  # 16-byte key
        self.encryptor = AESEncryptor(self.key)
        self.sample_data = b'Hello, AES Encryption!'

    def test_encrypt_decrypt(self):
        # Tes enkripsi dan dekripsi
        encrypted = self.encryptor.encrypt(self.sample_data)
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        decrypted = self.encryptor.decrypt(iv, ciphertext)
        self.assertEqual(decrypted, self.sample_data)


class TestFileEncryptor(unittest.TestCase):
    
    @patch.object(FileEncryptor, 'browse_file')  # Mocking browse_file method
    @patch.object(FileEncryptor, 'get_file_type')  # Mocking get_file_type method
    def setUp(self, mock_get_file_type, mock_browse_file):
        # Setup untuk FileEncryptor
        self.entry_file = MagicMock()
        self.entry_key = MagicMock()
        self.label_result = MagicMock()
        
        self.file_encryptor = FileEncryptor(self.entry_file, self.entry_key, self.label_result)
        mock_get_file_type.return_value = "Teks"
        
        # Data file dan key
        self.filename = 'AES_Encryption_Test.docx'
        self.key = '1234567890123456'

    def test_encrypt_file_valid(self):
        # Setup untuk file enkripsi
        self.entry_file.get.return_value = self.filename
        self.entry_key.get.return_value = self.key
        mock_file_handler = MagicMock()
        mock_file_handler.read_file.return_value = b'File data'
        mock_file_handler.validate_key.return_value = True
        
        # Tes enkripsi
        with patch.object(FileHandler, 'write_file') as mock_write_file:
            self.file_encryptor.encrypt_file()
            mock_write_file.assert_called_once()  # Memastikan file berhasil ditulis

    def test_decrypt_file_valid(self):
        # Setup untuk file dekripsi
        self.entry_file.get.return_value = self.filename + '.encrypted'
        self.entry_key.get.return_value = self.key
        mock_file_handler = MagicMock()
        mock_file_handler.read_file.return_value = b'Encrypted file data'
        mock_file_handler.validate_key.return_value = True
        
        # Tes dekripsi
        with patch.object(FileHandler, 'write_file') as mock_write_file:
            self.file_encryptor.decrypt_file()
            mock_write_file.assert_called_once()  # Memastikan file berhasil ditulis

    def test_encrypt_file_invalid_key(self):
        # Test jika panjang kunci tidak valid
        self.entry_file.get.return_value = self.filename
        self.entry_key.get.return_value = 'shortkey'  # Key yang tidak valid
        with patch.object(messagebox, 'showerror') as mock_showerror:
            self.file_encryptor.encrypt_file()
            mock_showerror.assert_called_once_with("Error", "Panjang kunci harus 16, 24, atau 32 karakter")

    def test_decrypt_file_invalid_extension(self):
        # Test jika file yang dipilih bukan file terenkripsi
        self.entry_file.get.return_value = self.filename
        self.entry_key.get.return_value = self.key
        with patch.object(messagebox, 'showerror') as mock_showerror:
            self.file_encryptor.decrypt_file()
            mock_showerror.assert_called_once_with("Error", "File yang dipilih bukan file terenkripsi (.encrypted)")

    def test_refresh(self):
        # Tes refresh untuk mengatur ulang status
        self.entry_file.delete = MagicMock()
        self.entry_key.delete = MagicMock()
        self.label_result.config = MagicMock()
        
        self.file_encryptor.refresh()
        
        self.entry_file.delete.assert_called_once()
        self.entry_key.delete.assert_called_once()
        self.label_result.config.assert_called_once_with(text="Status: - | Waktu Proses: - | Tipe: -")

class TestTimer(unittest.TestCase):

    def test_timer(self):
        timer = Timer()
        timer.start()
        time.sleep(1)  # Tunggu 1 detik
        timer.stop()
        elapsed = timer.elapsed_time()
        self.assertGreater(elapsed, 0)  # Memastikan waktu yang berlalu lebih besar dari 0

if __name__ == '__main__':
    unittest.main()
