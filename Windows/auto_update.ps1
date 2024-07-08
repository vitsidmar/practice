Write-Host "Installing PSWindowsUpdate module..."
try {
    Install-Module -Name PSWindowsUpdate -Force -AllowClobber -ErrorAction Stop
    Write-Host "PSWindowsUpdate module installed successfully."
} catch {
    Write-Host "Failed to install PSWindowsUpdate module: $_"
    exit 1
}

Write-Host "Importing PSWindowsUpdate module..."
try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
    Write-Host "PSWindowsUpdate module imported successfully."
} catch {
    Write-Host "Failed to import PSWindowsUpdate module: $_"
    exit 1
}

Write-Host "Setting execution policy..."
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force -ErrorAction Stop
    Write-Host "Execution policy set successfully."
} catch {
    Write-Host "Failed to set execution policy: $_"
    exit 1
}

Write-Host "Starting Windows Update..."
try {
    $updates = Get-WindowsUpdate -ErrorAction Stop
    if ($updates.Count -eq 0) {
        Write-Host "No updates available."
            
        $taskName = "UpdateTask"
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Host "Scheduled task '$taskName' has been removed."
        } catch {
            Write-Host "Failed to remove scheduled task: $_"
        }

        $scriptPath = "C:\auto_update.ps1" # Замініть на реальний шлях до вашого файлу скрипта
        try {
            Remove-Item -Path $scriptPath -ErrorAction Stop
            Write-Host "Script file removed successfully."
        } catch {
            Write-Host "Failed to remove script file: $_"
        }
    
    } else {
        Write-Host "$($updates.Count) updates found. Installing updates..."
        Install-WindowsUpdate -AcceptAll -InstallAll -AutoReboot -ErrorAction Stop
        Write-Host "Updates installed successfully."
    }
} catch {
    Write-Host "An error occurred during Windows Update: $_"
    exit 1
}

Write-Host "Windows Update process completed."
