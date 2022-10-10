Invoke-Expression "cmd.exe /c ntdsutil 'activate instance ntds' ifm 'create full .\audit'q q q"

Import-Module .\DSInternals\DSInternals.psd1

$count=0
$PwHits=@{}
$DomainPasswords = @()
$UsersWithBadPasswords = @()
$BadPasswords = Import-Csv .\test-hashes.txt


Get-ADDBAccount -All -DBPath '.\audit\Active Directory\ntds.dit' -BootKey (Get-BootKey -SystemHivePath .\audit\registry\SYSTEM) | ForEach-Object {
    $count += 1;

    try{
        $hash = (ConvertTo-Hex $_.NTHash).ToUpper().ToString();

        $DomainPasswords += $hash;

        if (($BadPasswords | where {$hash -match $_.Hash})){
            if ($PwHits.Contains($hash)){
                $PwHits[$hash]+= 1
                $UsersWithBadPasswords += $_.SamAccountName
            }
            else {
                $PwHits.Add($hash,1)
                $UsersWithBadPasswords += $_.SamAccountName
            }
        }
    }
    catch
    {}

    if ($count%100 -eq 0)
        {Write-Host "Processed $count passwords"}

    
}

$PwHits.GetEnumerator() | Select-Object -Property Key,Value | Export-Csv -NoTypeInformation -Path ".\AUDIT_Common_Hashes_Found.csv"

$DomainPasswords | Group-Object -NoElement | select Count,Name | Sort-Object Count -Descending | Select-Object -First 10 | Export-Csv -NoTypeInformation -Path ".\AUDIT_Top_Domain_Hashes.csv"

$UsersWithBadPasswords | group-object -NoElement | select Name | Export-Csv -NoTypeInformation -Path ".\AUDIT_Users_With_Bad_Passwords.csv"


Invoke-Expression "cmd.exe /c .\sdelete64.exe -accepteula -p 7 -r -s .\audit"

