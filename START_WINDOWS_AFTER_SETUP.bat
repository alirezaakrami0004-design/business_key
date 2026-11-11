@echo off
cd /d %~dp0
call .venv\Scripts\activate
python -m waitress --listen=127.0.0.1:8000 app:app
pause
