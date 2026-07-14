# Password_Audit.ps1  (optimized)

Invoke-Expression "cmd.exe /c ntdsutil 'activate instance ntds' ifm 'create full .\audit'q q q"

Import-Module .\DSInternals\DSInternals.psd1

# --- Load the known-bad hashes ONCE into a case-insensitive HashSet for O(1) lookups ---
$BadHashes = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
Import-Csv .\common-hashes.txt | ForEach-Object { [void]$BadHashes.Add($_.Hash) }

# --- Accumulators: Lists / hashtables instead of += arrays ---
$count                 = 0
$PwHits                = @{}                                             # bad hash -> {Total; Enabled; Disabled} counts
$DomainHashCounts      = @{}                                             # every hash -> frequency (for "most reused")
$UsersWithBadPasswords = [System.Collections.Generic.List[object]]::new()

$BootKey = Get-BootKey -SystemHivePath .\audit\registry\SYSTEM

# foreach statement instead of the ForEach-Object pipeline: lower per-iteration
# overhead. Note this materializes all accounts in memory first (fine at 25-50k).
foreach ($acct in (Get-ADDBAccount -All -DBPath '.\audit\Active Directory\ntds.dit' -BootKey $BootKey)) {
    $count++

    if ($null -eq $acct.NTHash) { continue }   # skip accounts with no stored NT hash (replaces the blanket try/catch)

    $hash = (ConvertTo-Hex $acct.NTHash).ToUpper()

    # Frequency of every hash in the domain (counted inline, no giant array)
    if ($DomainHashCounts.ContainsKey($hash)) { $DomainHashCounts[$hash]++ }
    else                                      { $DomainHashCounts[$hash] = 1 }

    # O(1) membership test instead of piping the whole list through Where-Object + regex
    if ($BadHashes.Contains($hash)) {
        if (-not $PwHits.ContainsKey($hash)) {
            $PwHits[$hash] = [pscustomobject]@{ Hash = $hash; Total = 0; EnabledCount = 0; DisabledCount = 0 }
        }
        $entry = $PwHits[$hash]
        $entry.Total++
        if ($acct.Enabled) { $entry.EnabledCount++ } else { $entry.DisabledCount++ }

        $UsersWithBadPasswords.Add([pscustomobject]@{
            SamAccountName = $acct.SamAccountName
            Enabled        = $acct.Enabled
        })
    }

    if ($count % 1000 -eq 0) { Write-Host "Processed $count accounts" }
}

# --- Reports (unchanged outputs) ---
$PwHits.Values |
    Sort-Object Total -Descending |
    Select-Object Hash, Total, EnabledCount, DisabledCount |
    Export-Csv -NoTypeInformation -Path ".\AUDIT_Common_Hashes_Found.csv"

$DomainHashCounts.GetEnumerator() |
    Sort-Object Value -Descending |
    Select-Object -First 10 |
    Select-Object @{Name='Count';Expression={$_.Value}}, @{Name='Name';Expression={$_.Key}} |
    Export-Csv -NoTypeInformation -Path ".\AUDIT_Top_Domain_Hashes.csv"

$UsersWithBadPasswords |
    Sort-Object Enabled -Descending |
    Select-Object SamAccountName, Enabled |
    Export-Csv -NoTypeInformation -Path ".\AUDIT_Users_With_Bad_Passwords.csv"

Invoke-Expression "cmd.exe /c .\sdelete64.exe -accepteula -p 7 -r -s .\audit"
