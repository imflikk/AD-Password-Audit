# Overview
This script is intended to be run on a domain controller to audit an Active Directory environment for weak/common passwords.  It uses [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) to iterate through AD users and check for common/weak passwords, output three files detailing the information found, and securely deletes the AD backup data when finished.

It performs the following steps:

1. Use the built-in ntdsutil tool to create a backup of the current AD information.
2. Imports DSInternals to parse the backup for all individual user accounts.
3. If a user's NTLM hash matches one provided in the 'common-hashes.txt' file, it is added to a list that will be written out at the end.
4. Write three CSV files when the script is finished:
    - *AUDIT_Common_Hashes_Found.csv* - Any hashes found in use (without the matching user) that match ones provided in 'common-hashes.txt', to identify what weak passwords are being used.
    - *AUDIT_Top_Domain_Hashes.csv* - The top 10 hashes seen in the environment, to identify if any passwords are in widespread use across the environment.
    - *AUDIT_Users_With_Bad_Passwords.csv* - Any users seen using a hash in 'common-hashes.txt' (without the matching hash), to identify which users should likely reset their passwords.
5. Use [sdelete64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete) to securely delete the AD backup data

> **NOTE**: Although no user/hash combinations are saved in any one file, they can obviously be figured out without much trouble by comparing the files.  Because of this, these files should be treated as extremely sensitive.  The alternative is to comment out/remove one of the lines in the script (currently lines 40, 42, and 44) to prevent one or more of the files from being created.

# Requirements
The only external requirement, apart from being run on a domain controller, is that .NET Framework 4.6 or later is installed.  This is required for the DSInternals modules to function correctly.

# Usage
The script does not require any arguments and can be loaded directly in a PowerShell prompt from the directory the repository's contents were downloaded to.

```powershell
PS C:\Users\Administrator\Downloads\PasswordAudit> .\Password_Audit.ps1
```

The 'common-hashes.txt' file, from line 2 onward (line one needs to remain 'Hash'), should be filled with the NTLM hash of any common passwords you would like to compare against.  [This site](https://tobtu.com/lmntlm.php) is useful for converting multiple passwords into hashes at once.  The only hash in the file currently is for the password 'Password1@'.

# Example Output

```default
PS C:\Users\Administrator\Downloads\PasswordAudit> .\Password_Audit.ps1
ntdsutil: activate instance ntds
Active instance set to "ntds".
ntdsutil: ifm
ifm: create full .\audit
Creating snapshot...
Snapshot set {a7d2ff46-a16e-4f8a-bdad-9586b3d2d10c} generated successfully.
Snapshot {d9cfe93a-f25b-40cc-8988-5d4f157f7fc8} mounted as C:\$SNAP_202210100908_VOLUMEC$\
Snapshot {d9cfe93a-f25b-40cc-8988-5d4f157f7fc8} is already mounted.
Initiating DEFRAGMENTATION mode...
     Source Database: C:\$SNAP_202210100908_VOLUMEC$\Windows\NTDS\ntds.dit
     Target Database: C:\Users\Administrator\Downloads\PasswordAudit\audit\Active Directory\ntds.dit

                  Defragmentation  Status (omplete)

          0    10   20   30   40   50   60   70   80   90  100
          |----|----|----|----|----|----|----|----|----|----|
          ...................................................

Copying registry files...
Copying C:\Users\Administrator\Downloads\PasswordAudit\audit\registry\SYSTEM
Copying C:\Users\Administrator\Downloads\PasswordAudit\audit\registry\SECURITY
Snapshot {d9cfe93a-f25b-40cc-8988-5d4f157f7fc8} unmounted.
IFM media created successfully in C:\Users\Administrator\Downloads\PasswordAudit\audit
ifm: q
ntdsutil: q

SDelete v2.02 - Secure file delete
Copyright (C) 1999-2018 Mark Russinovich
Sysinternals - www.sysinternals.com

SDelete is set for 7 passes.
.\audit\Active Directory\ntds.dit...deleted.
.\audit\Active Directory\ntds.jfm...deleted.
.\audit\registry\SECURITY...deleted.
.\audit\registry\SYSTEM...deleted.
.\audit\registry\SYSTEM.LOG1...deleted.
.\audit\registry\SYSTEM.LOG2...deleted.
.\audit\registry\SYSTEM{14499440-48b5-11ed-a4f4-000c29f2d493}.TM.blf...deleted.
.\audit\registry\SYSTEM{14499440-48b5-11ed-a4f4-000c29f2d493}.TMContainer00000000000000000001.regtrans-ms...deleted.
.\audit\registry\SYSTEM{14499440-48b5-11ed-a4f4-000c29f2d493}.TMContainer00000000000000000002.regtrans-ms...deleted.

Files deleted: 9
Directories deleted: 3
```

# License
See the LICENSE file.