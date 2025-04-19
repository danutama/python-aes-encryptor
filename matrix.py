import pandas as pd

data = {
    "Panjang Kunci (bit)": [128, 128, 192, 192, 256, 256],
    "Jumlah Kemungkinan Kunci": ["3.4 x 10^38", "3.4 x 10^38", "6.277 x 10^57", "6.277 x 10^57", "1.158 x 10^77", "1.158 x 10^77"],
    "Laju Pencarian Kunci": ["1 juta kunci/detik", "1 juta kunci/milidetik", "1 juta kunci/detik", "1 juta kunci/milidetik", "1 juta kunci/detik", "1 juta kunci/milidetik"],
    "Waktu (detik)": ["3.4 x 10^32", "3.4 x 10^29", "6.277 x 10^51", "6.277 x 10^48", "1.158 x 10^71", "1.158 x 10^68"],
    "Waktu (tahun)": ["1.078 x 10^25", "1.078 x 10^22", "1.991 x 10^44", "1.991 x 10^41", "3.671 x 10^63", "3.671 x 10^60"]
}

df = pd.DataFrame(data)
print(df)
