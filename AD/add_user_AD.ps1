#CSV Login; Password; LastName; FirstName; MiddleName; OU; JobTitle
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
    $domain = [Microsoft.VisualBasic.Interaction]::InputBox("Geben Sie die Domain im Format migrate.local ein", "Domain Auswahl", "migrate.local")
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

        # Abrufen aller Organisationseinheiten
        $allou = Get-ADOrganizationalUnit -Filter * -SearchBase "DC=$($domain -replace '\.',',DC=')"

        foreach ($User in $Users) {
            # Suchen der entsprechenden OU
            $ou = $allou | Where-Object {$_.Name -eq $User.OU}
            
            # Verwenden der gefundenen OU oder der Standard-OU
            if ($ou) {
                $OU = $ou.DistinguishedName
            } else {
                $OU = "OU=Andere,DC=$($domain -replace '\.',',DC=')"  # Wenn der Katalog mit diesem Namen nicht gefunden wird, senden wir ihn an OU "Andere"
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
