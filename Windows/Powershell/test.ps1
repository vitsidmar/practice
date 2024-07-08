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
    $domain = [Microsoft.VisualBasic.Interaction]::InputBox("Введіть домен у форматі ss.net.ua", "Вибір домену", "ss.net.ua")
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

        foreach ($User in $Users) {
            # Пошук відповідної OU
            $ou = $allou | Where-Object {$_.Name -eq $User.OU}
            
            # Використання знайденої OU або дефолтної OU
            if ($ou) {
                $OU = $ou.DistinguishedName
            } else {
                $OU = "OU=Others,DC=$($domain -replace '\.',',DC=')"  # Якщо каталог з таким ім'ям не знайдено, відправляємо в OU "Others"
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
