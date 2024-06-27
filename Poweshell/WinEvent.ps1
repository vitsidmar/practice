# Festlegen des Zeitraums zum Filtern der Ereignisse
$startDate = (Get-Date).AddDays(-7)  # Letzten 7 Tage
$endDate = Get-Date

# Abfrage des Ereignisprotokolls zur Ermittlung fehlgeschlagener Anmeldeversuche (Ereignis-ID 4625)
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $startDate
    EndTime = $endDate
} -ErrorAction SilentlyContinue

# Überprüfen der Anzahl der gefundenen Ereignisse
if ($events -eq $null -or $events.Count -eq 0) {
    $body = "Keine fehlgeschlagenen Anmeldeversuche in den letzten 7 Tagen."
} else {
    # Auswahl der relevanten Eigenschaften
    $events = $events | Select-Object TimeCreated, Id, Message
    
    # Ausgabe der Anzahl fehlgeschlagener Anmeldeversuche
    $totalFailedAttempts = $events.Count
    $body = "Anzahl fehlgeschlagener Anmeldeversuche in den letzten 7 Tagen: $totalFailedAttempts`n`n"
    
    # Erstellen des Berichts als CSV-Datei
    $reportPath = "C:\Temp\FailedLogonAttemptsReport.csv"
    $events | Export-Csv -Path $reportPath -NoTypeInformation

    $body += "Bericht erstellt unter: $reportPath"
}

# E-Mail Parameter
$smtpServer = "smtp.migrate.local"
$from = "winevent@smtp.migrate.lokal"
$to = "vitalii.stepchuk@sidmar.ch"
$subject = "Bericht über fehlgeschlagene Anmeldeversuche"
$body = $body

# Send-MailMessage zur Übermittlung des Berichts
Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body

# Ausgabe des Ergebnisses auf der Konsole
Write-Host $body
