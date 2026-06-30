#!/bin/bash

git add .

git status

echo
read -p "Commit message: " MSG

git commit -m "$MSG"

git push origin main
