# adcert revocation worklist - generated 2026-07-24T20:42:35+0000
# Review before executing. Commands run with -WhatIf by default;
# set $Commit = $true only after verifying the worklist.
$Commit = $false
$Flag = if ($Commit) { @{} } else { @{ WhatIf = $true } }
Import-Module ActiveDirectory

# jsmith <- App-Admins  (reviewer: manager1) - Account disabled at separation; membership should have been removed.
Remove-ADGroupMember -Identity 'App-Admins' -Members 'jsmith' -Confirm:$false @Flag

# jsmith <- VPN-Users  (reviewer: manager1) - Account disabled at separation; membership should have been removed.
Remove-ADGroupMember -Identity 'VPN-Users' -Members 'jsmith' -Confirm:$false @Flag

