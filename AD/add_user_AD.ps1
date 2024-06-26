# CSV: Login; Password; LastName; FirstName; MiddleName; OU; JobTitle
# powershell -ExecutionPolicy Bypass -File C:\User\vital\Downloads\add_user_AD.ps1
# Імпорт модуля Active Directory
Import-Module ActiveDirectory

# Функція для вибору файлу через діалогове вікно
function Select-FileDialog {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "CSV files (*.csv)|*.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    return $OpenFileDialog.FileName
}

# Функція для введення домену через діалогове вікно
function Get-DomainInput {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $domain = [Microsoft.VisualBasic.Interaction]::InputBox("Введіть домен у форматі migrate.local", "Вибір домену", "migrate.local")
    return $domain
}

# Введення домену через діалогове вікно
$domain = Get-DomainInput

# Перевірка, чи домен був введений
if ($domain -ne "") {
    # Виклик функції для вибору файлу
    $csvPath = Select-FileDialog

    # Перевірка, чи файл був вибрано
    if ($csvPath -ne "") {
        # Імпорт CSV файлу з вказаним роздільником
        $Users = Import-Csv -Path $csvPath -Delimiter ';'

        # Отримання всіх організаційних одиниць
        $allou = Get-ADOrganizationalUnit -Filter * -SearchBase "DC=$($domain -replace '\.',',DC=')"

        # Пошук або створення організаційної одиниці "Andere" (інші)
        $OtherOU = $allou | Where-Object {$_.Name -eq "Andere"}
        if (-not $OtherOU) {
            $OtherOU = New-ADOrganizationalUnit -Name "Andere" -Path "DC=$($domain -replace '\.',',DC=')"
            Write-Host "Створено нову організаційну одиницю 'Andere'."
        }

        foreach ($User in $Users) {
            # Пошук відповідної OU
            $ou = $allou | Where-Object {$_.Name -eq $User.OU}
            
            # Використання знайденої OU або створення нової "Andere"
            if ($ou) {
                $OU = $ou.DistinguishedName
            } else {
                $OU = $OtherOU.DistinguishedName
            }
            
            # Зчитування даних користувача
            $Password = $User.Password
            $Detailedname = $User.LastName + " " + $User.FirstName + " " + $User.MiddleName
            $UserFirstname = $User.FirstName
            $UserLastName = $User.LastName
            $JobTitle = $User.JobTitle
            $SAM = $User.Login + "@$domain"
            
            try {
                # Створення нового користувача в Active Directory
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
                
                Write-Host "Користувач $($User.Login) створений успішно."
            } catch {
                Write-Host "Помилка створення користувача $($User.Login): $_"
            }
        }

        Write-Host "Процес створення користувачів завершено."
    } else {
        Write-Host "Файл не було вибрано."
    }
} else {
    Write-Host "Домен не було введено."
}
