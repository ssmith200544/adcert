# adcert revocation worklist — generated 2026-07-18T12:22:57+0000
# Review before executing. Commands run with -WhatIf by default;
# set $Commit = $true only after verifying the worklist.
$Commit = $false
$Flag = if ($Commit) { @{} } else { @{ WhatIf = $true } }
Import-Module ActiveDirectory

# ebergström <- Enclave-HPC-Users  (reviewer: costrom) — Account disabled at separation; membership should have been removed.
Remove-ADGroupMember -Identity 'Enclave-HPC-Users' -Members 'ebergström' -Confirm:$false @Flag

