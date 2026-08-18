if (-Not (Get-Variable psISE -ea 0)) {
    $ExecDir = $MyInvocation.MyCommand.Path.Substring(0,$($MyInvocation.MyCommand.Path.LastIndexOf("\")))
    $Scriptname = $MyInvocation.MyCommand.Path.Substring($($MyInvocation.MyCommand.Path.LastIndexOf("\") + 1)).replace(".ps1","")
} else {
    $ExecDir = $psISE.CurrentFile.FullPath.Substring(0,$($psISE.CurrentFile.FullPath.LastIndexOf("\")))
    $Scriptname = $psISE.CurrentFile.FullPath.Substring($($psISE.CurrentFile.FullPath.LastIndexOf("\") + 1)).replace(".ps1","")
}

Start-Transcript -Path "$ExecDir\$Scriptname.log" -Append
$MaxCopiesLongCount = 156
$MaxCopiesShortCount = 120

$AllSystemVolumes = Get-Volume | select DriveLetter,UniqueId
$AllCopies = Get-CimInstance -ClassName Win32_ShadowCopy | select VolumeName,@{name='VolumeLabel';exp={($AllSystemVolumes[$AllSystemVolumes.UniqueId.IndexOf($_.VolumeName)]).DriveLetter}},ID,InstallDate,ClientAccessible #All existed shadow copies
$AllShadowVolumes = (Get-CimInstance -ClassName Win32_ShadowStorage | Select-Object -Property Volume).Volume.DeviceID # List Shadow copy enabled Volumes

Write-Host "System is configured for holding max $((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\VSS\Settings -Name "MaxShadowCopies").MaxShadowCopies) shadow copies per volume" -ForegroundColor Yellow
Write-Host "This Script cuts oldest shadow copies for saving only $($MaxCopiesLongCount - 1) LONG and $($MaxCopiesShortCount - 1) SHORT copies per volume. Total $($MaxCopiesLongCount + $MaxCopiesShortCount) per volume."
Write-HOst "Starting execution:"

$AllShadowVolumes | % {
    $Volume = $_
    $VolumeLabel = ($AllSystemVolumes[$AllSystemVolumes.UniqueId.IndexOf($Volume)]).DriveLetter + ":"
    Write-Host "$VolumeLabel $Volume" -ForegroundColor Yellow
    $CopiesLong = $AllCopies | ? {$_.VolumeName -eq $Volume} | ? {$_.ClientAccessible} | ? {$_.InstallDate.Hour -eq 0}
    Write-Host "Exists $($CopiesLong.Count) LONG copies for Volume $VolumeLabel"
    $CopiesShort = $AllCopies | ? {$_.VolumeName -eq $Volume} | ? {$_.ClientAccessible} | ? {$_.InstallDate.Hour -ne 0}
    Write-Host "Exists $($CopiesShort.Count) SHORT copies for Volume $VolumeLabel"
    If ($CopiesLong.Count -ge $MaxCopiesLongCount) {
        0..$($CopiesLong.Count - $MaxCopiesLongCount) | % {
            Write-Host "Deleting LONG Snapshot with ID $($CopiesLong[$_].ID) and timestamp $($CopiesLong[$_].InstallDate)on on Volume $VolumeLabel" -ForegroundColor Cyan
            vssadmin Delete Shadows /Shadow=$($CopiesLong[$_].ID) /Quiet
        }
    } else {Write-Host "No LONG Shadow Copies for deleteion on Volume $VolumeLabel"}
    If ($CopiesShort.Count -ge $MaxCopiesShortCount) {
        0..$($CopiesShort.Count - $MaxCopiesShortCount) | % {
            Write-Host "Deleting SHORT Snapshot with ID $($CopiesShort[$_].ID) and timestamp $($CopiesShort[$_].InstallDate)on Volume $VolumeLabel" -ForegroundColor Cyan
            vssadmin Delete Shadows /Shadow=$($CopiesShort[$_].ID) /Quiet
        }
    } else {Write-Host "No SHORT Shadow Copies for deleteion on Volume $VolumeLabel"}
    Write-Host "Starting devnodeclean"
    & cmd /c "$Execdir\devnodeclean\x64\DevNodeClean.exe"
}
Stop-Transcript