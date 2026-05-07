@echo off
title NetShield AI Launcher

cd /d "%~dp0"

echo ============================================
echo        STARTING NETSHIELD AI
echo ============================================

python -m streamlit run app.py

pause