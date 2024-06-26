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
    Write-Host "Keine fehlgeschlagenen Anmeldeversuche in den letzten 7 Tagen."
} else {
    # Auswahl der relevanten Eigenschaften
    $events = $events | Select-Object TimeCreated, Id, Message
    
    # Ausgabe der Anzahl fehlgeschlagener Anmeldeversuche
    $totalFailedAttempts = $events.Count
    Write-Host "Anzahl fehlgeschlagener Anmeldeversuche in den letzten 7 Tagen: $totalFailedAttempts"

    # Erstellen des Berichts als CSV-Datei
    $reportPath = "C:\Temp\FailedLogonAttemptsReport.csv"
    $events | Export-Csv -Path $reportPath -NoTypeInformation

    Write-Host "Bericht erstellt unter: $reportPath"
}
