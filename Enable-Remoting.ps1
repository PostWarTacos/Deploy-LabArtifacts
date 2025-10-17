# Define user and password variables
$user = 'student'
$pass = 'Training1'

# Create credential object from variables
$securePass = ConvertTo-SecureString $pass -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($user, $securePass)

foreach ( $t in $targets ){
    Write-Host "Enabling PS Remoting on $t"
    Start-Process -FilePath ".\Enable-Remoting.bat" -ArgumentList $t -Wait -PassThru -NoNewWindow
    Invoke-Command -ComputerName $t -Credential $creds -ScriptBlock { .\Enable-Remoting.ps1 }
}