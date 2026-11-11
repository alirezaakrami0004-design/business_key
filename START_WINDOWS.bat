@echo off
cd /d %~dp0
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
python -m pip install -r requirements.txt
if not exist .env copy .env.example .env
echo.
echo .env را باز کنید و کلید API و منابع خبری را تنظیم کنید.
echo سپس دوباره START_WINDOWS.bat را اجرا کنید.
pause
python -m waitress --listen=127.0.0.1:8000 app:app
pause
