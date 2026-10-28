# Push AgentWarden to https://github.com/nishat09/Agent_Warden
# Run from anywhere:  powershell -File "D:\Cybersecurity Projects\Ai security Project\scripts\push-github.ps1"

$ErrorActionPreference = "Stop"
Set-Location "D:\Cybersecurity Projects\Ai security Project"

# Free a little C: space so git/credential helpers can write
Remove-Item "$env:TEMP\aw2","$env:TEMP\aw3","$env:TEMP\aw-edge-profile" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem "$env:TEMP" -Filter "Ollama*" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

if (-not (git diff --quiet -- README.md) -or -not (git diff --cached --quiet -- README.md)) {
    git add README.md .gitignore
    git commit -m "README: who this is for (local Ollama vs hosted Grok/GPT)"
}

if (git remote | Select-String -Quiet "^origin$") {
    git remote set-url origin "https://github.com/nishat09/Agent_Warden.git"
} else {
    git remote add origin "https://github.com/nishat09/Agent_Warden.git"
}

git branch -M main
git push -u origin main
Write-Host "Pushed to https://github.com/nishat09/Agent_Warden"
