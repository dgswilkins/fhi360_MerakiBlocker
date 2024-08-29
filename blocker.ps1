Push-Location 'D:\fhi360_MerakiBlocker'
& .\.venv\Scripts\Activate.ps1
python src\mac_blocker.py
deactivate
Pop-Location