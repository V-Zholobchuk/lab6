# Система управління обліковими записами (Лабораторна робота №6)

Вебзастосунок на Python (Flask + SQLite) з реалізацією:
- розмежування доступу на основі ролей (RBAC: користувач та адміністратор);
- політики паролів та хешування PBKDF2-HMAC-SHA256;
- графічної CAPTCHA при реєстрації;
- активації облікового запису та відновлення пароля через електронну пошту (SMTP);
- захисту від Brute Force та журналу логування входів;
- двофакторної автентифікації 2FA (TOTP через Google Authenticator з QR-кодом або OTP на Email);
- входу через зовнішні сервіси (Google OpenID Connect / GitHub OAuth 2.0).

## Налаштування та запуск

1. Встановіть залежності:
   ```bash
   pip install -r requirements.txt
   ```
2. Створіть файл `.env` на основі `.env.example` і вкажіть свої дані (`SMTP_USER`, `SMTP_PASSWORD`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` або `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`).
3. Запустіть сервер:
   ```bash
   python app.py
   ```
4. Відкрийте `http://127.0.0.1:5000`
