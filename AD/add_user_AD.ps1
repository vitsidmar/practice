# CSV: Login; Password; LastName; FirstName; MiddleName; OU; JobTitle
# powershell -ExecutionPolicy Bypass -File C:\User\vital\Downloads\add_user_AD.ps1
# Import des Active Directory-Moduls
Import-Module ActiveDirectory

# Funktion für die Auswahl einer Datei über ein Dialogfenster
function Select-FileDialog {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "CSV-Dateien (*.csv)|*.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    return $OpenFileDialog.FileName
}

# Funktion für die Eingabe der Domain über ein Dialogfenster
function Get-DomainInput {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $domain = [Microsoft.VisualBasic.Interaction]::InputBox("Geben Sie die Domain im Format ss.net.ua ein", "Domain Auswahl", "ss.net.ua")
    return $domain
}

# Eingabe der Domain über ein Dialogfenster
$domain = Get-DomainInput

# Überprüfung, ob die Domain eingegeben wurde
if ($domain -ne "") {
    # Aufruf der Funktion zur Auswahl der Datei
    $csvPath = Select-FileDialog

    # Überprüfung, ob eine Datei ausgewählt wurde
    if ($csvPath -ne "") {
        # Importieren der CSV-Datei mit dem angegebenen Trennzeichen
        $Users = Import-Csv -Path $csvPath -Delimiter ';'

        foreach ($User in $Users) {
            # Suchen der entsprechenden OU
            $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$($User.OU)'" -SearchBase "DC=$($domain -replace '\.',',DC=')"
            
            # Verwenden der gefundenen OU oder Erstellen einer neuen OU
            if ($ou) {
                $OU = $ou.DistinguishedName
            } else {
                $newOUName = $User.OU
                $newOUDN = "OU=$newOUName,DC=$($domain -replace '\.',',DC=')"
                
                try {
                    # Erstellen einer neuen OU, wenn sie nicht vorhanden ist
                    New-ADOrganizationalUnit -Name $newOUName -Path "DC=$($domain -replace '\.',',DC=')"
                    
                    $OU = $newOUDN
                    Write-Host "Neue OU '$newOUName' wurde erfolgreich erstellt."
                } catch {
                    Write-Host "Fehler beim Erstellen der OU '$newOUName': $_"
                    # Setze $OU auf eine Standard-OU oder handle den Fehler entsprechend
                    $OU = "OU=Andere,DC=$($domain -replace '\.',',DC=')"
                }
            }
            
            # Lesen der Benutzerdaten
            $Password = $User.Password
            $Detailedname = $User.LastName + " " + $User.FirstName + " " + $User.MiddleName
            $UserFirstname = $User.FirstName
            $UserLastName = $User.LastName
            $JobTitle = $User.JobTitle
            $SAM = $User.Login + "@$domain"
            
            try {
                # Erstellen eines neuen Benutzers im Active Directory
                New-ADUser -Name $Detailedname `
                    -SamAccountName $User.Login `
                    -UserPrincipalName $SAM `
                    -DisplayName $Detailedname `
                    -GivenName $User.FirstName `
                    -Surname $User.LastName `
                    -Title $JobTitle `
                    -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) `
                    -Enabled $true `
                    -Path $OU `
                    -ChangePasswordAtLogon $true
                
                Write-Host "Benutzer $($User.Login) erfolgreich erstellt."
            } catch {
                Write-Host "Fehler beim Erstellen des Benutzers $($User.Login): $_"
            }
        }

        Write-Host "Der Prozess zur Erstellung der Benutzer wurde abgeschlossen."
    } else {
        Write-Host "Es wurde keine Datei ausgewählt."
    }
} else {
    Write-Host "Die Domain wurde nicht eingegeben."
}

