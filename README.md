# Secure Notes

Şifreli not tutma uygulaması. Notlarınız yerel veritabanında AES-256 şifrelemesi ile saklanır.

## Özellikler

- Master password ile giriş
- AES-256-GCM şifreleme
- Not ekleme, düzenleme, silme
- Başlığa göre arama
- Brute-force koruması (başarısız denemelerde bekleme süresi)

## Gereksinimler

- Python 3.8+
- cryptography kütüphanesi

## Kurulum

```bash
pip install cryptography
python main.py
