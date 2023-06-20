cd $PSScriptRoot
Write-Host "Creating a virtual environment"
python -m venv .env
Write-Host "Activating the newly created virtual environment"
./.env/scripts/activate.ps1
Write-Host "Installing dependencies from requirements.txt"
pip install -r requirements.txt
Write-Host "Creating an executable"
pyinstaller --onefile decrypt_chrome_password.py
Write-Host "Deactivating the virtual environment"
deactivate
Remove-Item -Force -Recurse .env
Write-Host "Done"
