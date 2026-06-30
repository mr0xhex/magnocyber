#!/bin/bash

set -e

echo "================================="
echo "      MAGNOCYBER GIT PUSH"
echo "================================="

echo
git status

echo
read -p "Commit message: " MSG

git add .
git commit -m "$MSG"
git push origin main

echo
echo "[+] Commit enviado com sucesso."
