$EnableLoggingMailing = $true # Set to False for debug runs only

If ($EnableLoggingMailing) {
    $LogfileFullpath = "C:\Logs\iLO_SetParameters_DNS_$((get-date).DayOfWeek.value__).log"
    Start-Transcript -Path $LogfileFullpath -Force
    $SMTPServer = "exch.domain.local"
    $SenderEmailAddress = "iLO_SetParameters_DNS@domain.local"
    $RecivientsEmailAddress = "SysSupport@domain.local"
}

# Перечень подсетей $iLONetworks и отдельных хостов $iLOHosts с iLO
$iLONetworks = @("10.0.0";"10.0.1")
$iLOHosts = "10.1.0.1,10.1.13.2".Split(",") | Sort-Object | Get-Unique

# Перечень исключений, по этим хостам скрипт не ходит (не в нашей зоне ответственности)
[string[]]$iLOHostsExcluded = @()
#$iLOHostsExcluded += "".Split(",")

#Import-Module "C:\Program Files (x86)\Hewlett Packard Enterprise\PowerShell\Modules\HPEiLOCmdlets"
Import-Module "C:\HPEiLOCmdlets"
Import-Module dnsserver
Import-Module PSPKI | Out-Null #https://github.com/PKISolutions/PSPKI/releases/tag/v4.2.0

$ldapUser = 'CN=ilo_ldap_user,OU=Service_Users,OU=USERS_DOMAIN,DC=merlion,DC=local'
$ldapPassword_Encrypted = @"
-----BEGIN CMS-----

-----END CMS-----
"@
$ldapPassword_PlainText = Unprotect-CmsMessage -Content $ldapPassword_Encrypted

$iLOUser = 'Admin'
$iLOPassword_Encrypted_Admin = @"
-----BEGIN CMS-----

-----END CMS-----
"@
$iLOPassword_PlainText_Admin = Unprotect-CmsMessage -Content $iLOPassword_Encrypted_Admin
$iLOPassword_PlainText_Old_Admin = ''

#$iLONetworkObjects = $null ; $iLOHosts = $null ; $iLONetworks = $null
$iLONetworkObjects += $iLONetworks += $iLOHosts

$AllServers = $null
$iLONetworkObjects | % {
    If ($_ -like "*.*.*.*") {
        If ($((New-Object System.Net.Sockets.TcpClient).ConnectAsync(($_),443).Wait(999))) {
            [PSobject[]]$AllServers += Find-HPEiLO -Range $_
        } else {
            "$_ test connect tcp:443 failed"
        }
    } else {
        [PSobject[]]$AllServers += Find-HPEiLO -Range $_
    }
}
$AllServers = $AllServers.Where{($iLOHostsExcluded.IndexOf($_.IP) -eq -1)}

$DNSServerTypes = ,@("Primary","Secondary","Tertiary")
$DNSServers = ,@("","","")
$LDAPServer = "LDAP.domain.local"
$Zone = "domain.local"

$SNTPServers = "ntp.domain.local"

$TimeZone_iLO4 = "Europe/Moscow"
$TimeZone_iLO5 = 'Baghdad, Kuwait, Riyadh, Moscow, Istanbul, Nairobi'

# SSID групп которые нужно добавить в ACL
$grpsid1 = 'S-1-5-21-*' # ILO_USER_RW
$grpsid2 = 'S-1-5-21-*' # ILO_USER_RO

$grpName1 = (Get-ADGroup -Identity $grpsid1).Name
$grpName2 = (Get-ADGroup -Identity $grpsid2).Name

# Случайный сервер в списке серверов, с которым будем работать
$AllDNSServers = ($DNSServers[0] -join ",").Split(",")
$RandomIndex = Get-Random -Maximum $AllDNSServers.Count
$DNSServer = (Resolve-DnsName $($AllDNSServers[$RandomIndex])).NameHost # Случайный сервер в списке серверов, с которым будем работать

$CertExiredSafedays = 45 # Макс. количество дней до срока истечения сертификата, при котором начинается перевыпуск; минимальное - $CertExiredSafedays/3; реальное - случайное целое число в этом диапазоне
$CAConnectionPoint = "\" # Точка подключения к УЦ

$DiscoveredServers = ($AllServers).Hostname.replace(".domain.local","")
Write-Host "Discovered Servers: $($DiscoveredServers.Count)"
$iRecords = (Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType A | ? {($_.HostName -like "i-*") -and $_.TimeStamp}).HostName
Write-Host "i-* dynamic DNS records in zone: $($iRecords.Count)"

Write-Host "DNS records and Discovered Servers comparison:"
Compare-Object -ReferenceObject $iRecords -DifferenceObject $DiscoveredServers | Out-Host

function RegisterDnsRecord {
    $DNSHostName
    # Remove Record
    $OldObj = Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -name $DNSHostName -ea 0
    If ($OldObj) {Remove-DnsServerResourceRecord -InputObject $OldObj -ComputerName $DNSServer -ZoneName $Zone -Verbose -Force}
    # Ждем пока пропадет PTR, но не более 1 минуты
    Write-Host "Waiting for PTR autocleanup on DNS Server..." -fo Cyan
    $Timersec = 0
    While (($Timersec -lt 60) -and (Resolve-DnsName $_.IP -ea 0 -Server $DNSServer)) { Start-Sleep -Seconds 5 ; $Timersec += 5 }
    If ($Timersec -ge 60) {Write-Host "Clean PTR timeout reached"}
    # Create Record
    Add-DnsServerResourceRecordA -Name $DNSHostName -ComputerName $DNSServer -ZoneName $Zone -AllowUpdateAny -IPv4Address $_.IP -CreatePtr:$true -AgeRecord -Verbose
}

function Add-SANCertificateExtension {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BSTRCA,
        [Parameter(Mandatory = $true)]
        [int]$RequestID,
        [Parameter(Mandatory = $true)]
        [String[]]$AlternativeNames
    )
    function ConvertTo-DERstring ([byte[]]$bytes) {
        if ($bytes.Length % 2 -eq 1) {$bytes += 0}
        $SB = New-Object System.Text.StringBuilder
        for ($n = 0; $n -lt $bytes.count; $n += 2) {
            [void]$SB.Append([char]([int]$bytes[$n+1] -shl 8 -bor $bytes[$n]))
        }
        $SB.ToString()
    }    
    $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $IANs = New-Object -ComObject X509Enrollment.CAlternativeNames
    foreach ($SANstr in $AlternativeNames) {
        $IAN = New-Object -ComObject X509Enrollment.CAlternativeName
        #SAN types in https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
        $regex = [regex] "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        if (($regex.Matches($SANstr)).Success) {
            $IAN.InitializeFromRawData(8, 0x1, [Convert]::ToBase64String(([System.Net.IpAddress] $SANstr).GetAddressBytes()))
        } else {
            $IAN.InitializeFromString(0x3,$SANstr)
        }
        $IANs.Add($IAN)
    }
    $SAN.InitializeEncode($IANs)
    $bytes = [Convert]::FromBase64String($SAN.RawData(1))
    $pvarvalue = ConvertTo-DERstring $bytes
    $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
    $CertAdmin.SetCertificateExtension($BSTRCA,$RequestID,"2.5.29.17",0x3,0x0,$pvarvalue)
}

function ReIssueCertificate {
    New-Item -Path $env:TMP\$DNSHostName -ItemType Directory | Out-Null
    Start-HPEiLOCertificateSigningRequest -Connection $iLOSession -State "Moscow" -Country "RU" -City "" -Organization "" -OrganizationalUnit "" -CommonName $DNSHostName
    $Timeout = 0
    Do {Start-Sleep -Seconds 5 ; $Timeout += 5} Until (((Get-HPEiLOCertificateSigningRequest -Connection $iLOSession).CertificateSigningRequest) -or ($Timeout -gt 120))
    If ($Timeout -gt 120) {
        "Get-HPEiLOCertificateSigningRequest timeout. Resetting iLO..."
        Reset-HPEiLO -Connection $iLOSession -Device iLO -Confirm:$false
    } else {
        (Get-HPEiLOCertificateSigningRequest -Connection $iLOSession).CertificateSigningRequest | Out-File "$env:TMP\$DNSHostName\$DNSHostName.req"
        $Request = certreq -submit -config $CAConnectionPoint -attrib "CertificateTemplate:iLOWebServer" "$env:TMP\$DNSHostName\$DNSHostName.req" "$env:TMP\$DNSHostName\$DNSHostName.cer"
        $RequestID = [int](($Request.where({$_ -like "RequestId:*"})[0] -split " ")[1])
        Add-SANCertificateExtension $CAConnectionPoint $RequestID "$DNSHostName.domain.local",$DNSHostName,$_.ip
        Get-PendingRequest -CertificationAuthority (Get-CertificationAuthority)[0] -RequestID $RequestID | Approve-CertificateRequest
        certreq -config $CAConnectionPoint -retrieve $RequestID "$env:TMP\$DNSHostName\$DNSHostName SAN.cer"
        $certificate = Get-Content -Path "$env:TMP\$DNSHostName\$DNSHostName SAN.cer" -Raw
        Import-HPEiLOCertificate -Connection $iLOSession -Certificate $certificate | Out-Null
    }
    Remove-Item $env:TMP\$DNSHostName -Recurse
}

[Object[]]$ProcessedServers = $null
$AllServers | % {
    Write-Host "$($_.IP)`t$($_.Hostname)" -ForegroundColor Yellow
    $iLOSession = Connect-HPEiLO -Address $_.IP -Username $iLOUser -Password $iLOPassword_PlainText_Admin -DisableCertificateAuthentication -ea 0

    <#
    # Смена старого пароля
    If (-Not $iLOSession) {
        $iLOSession = Connect-HPEiLO -Address $_.IP -Username $iLOUser -Password $iLOPassword_PlainText_Old_Admin -DisableCertificateAuthentication
        Set-HPEiLOUser -Connection $iLOSession -LoginName $iLOUser -NewPassword $iLOPassword_PlainText_Admin
        Disconnect-HPEiLO -Connection $iLOSession
        $iLOSession = Connect-HPEiLO -Address $_.IP -Username $iLOUser -Password $iLOPassword_PlainText_Admin -DisableCertificateAuthentication -ea 0
    }
    #>

    If ($iLOSession) {
        $SkipNextSteps = $False

        $InterfaceType = (Get-HPEiLOIPv4NetworkSetting -Connection $iLOSession).InterfaceType

        ## Disable IPv6
        If ($InterfaceType -eq "Dedicated") {
            $CurrentIPv6NetworkSetting = Get-HPEiLOIPv6NetworkSetting -Connection $iLOSession

            If ($_.PN -like "*iLO 4*") {
                $Config = $true
                        "DHCPv6StatefulMode,DHCPv6StatelessMode,StatelessAddressAutoConfiguration,PreferredProtocol,RegisterDDNSServer".Split(",") | % {
                if ($CurrentIPv6NetworkSetting.$_ -ne "Disabled") {$Config = $False}
            }
                If (-Not $Config) {
                    Set-HPEiLOIPv6NetworkSetting -Connection $iLOSession -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -StatelessAddressAutoConfiguration Disabled -PreferredProtocol Disabled -RegisterDDNSServer Disabled
                    Reset-HPEiLO -Connection $iLOSession -Device iLO -Confirm:$false
                    $SkipNextSteps = $True
                }
            } else {
                $Config = $true
                "DHCPv6StatefulMode,DHCPv6StatelessMode,StatelessAddressAutoConfiguration,RegisterDDNSServer".Split(",") | % {
                    if ($CurrentIPv6NetworkSetting.$_ -ne "Disabled") {$Config = $False}
                }

                If (-Not $Config) {
                    Set-HPEiLOIPv6NetworkSetting -Connection $iLOSession -InterfaceType Dedicated -DHCPv6StatefulMode Disabled -DHCPv6StatelessMode Disabled -StatelessAddressAutoConfiguration Disabled -RegisterDDNSServer Disabled # HP bug. iLO5 dont accept key -PreferredProtocol Disabled
                    Reset-HPEiLO -Connection $iLOSession -Device iLO -Confirm:$false
                    $SkipNextSteps = $True
                }
            }
        }

        If (-Not $SkipNextSteps) {
            ## Set SNTP parameters
            $CurrentSNTPSettings = Get-HPEiLOSNTPSetting -Connection $iLOSession
            $CompareSntpServers = (Compare-Object -ReferenceObject $CurrentSNTPSettings.SNTPServer -DifferenceObject $SNTPServers)
    
            If ($_.PN -like "*iLO 4*") {
                if ($CompareSntpServers.Count -or ($CurrentSNTPSettings.Timezone -ne $TimeZone_iLO4)) {
                    Set-HPEiLOSNTPSetting -Connection $iLOSession -SNTPServer $SNTPServers -Timezone $TimeZone_iLO4 -InterfaceType $(((Get-HPEiLONICInfo -Connection $iLOSession).EthernetInterface | ? {$_.IPv4Address -eq (Get-HPEiLONICInfo -Connection $iLOSession).IP}).InterfaceType)
                    #Reset-HPEiLO -Connection $iLOSession -Device iLO -Confirm:$false
                    #Write-Host "Resetting iLO after apply NTP settings, skip next executions"
                    #$SkipNextSteps = $True
                }
            } else {
                if ($CompareSntpServers.Count -or ($CurrentSNTPSettings.Timezone -ne $TimeZone_iLO5)) {
                    Set-HPEiLOSNTPSetting -Connection $iLOSession -SNTPServer $SNTPServers -Timezone $TimeZone_iLO5 -InterfaceType $(((Get-HPEiLONICInfo -Connection $iLOSession).EthernetInterface | ? {$_.IPv4Address -eq (Get-HPEiLONICInfo -Connection $iLOSession).IP}).InterfaceType)
                    #Reset-HPEiLO -Connection $iLOSession -Device iLO -Confirm:$false
                    #Write-Host "Resetting iLO after apply NTP settings, skip next executions"
                    #$SkipNextSteps = $True
                }
            }
        }

        If (-Not $SkipNextSteps) {
            ## Set DNS Servers and domain name
            $CurrentDNSServers = Get-HPEiLOIPv4NetworkSetting -Connection $iLOSession

            If (Compare-Object -ReferenceObject $($DNSServers[0] -join ",") -DifferenceObject ($CurrentDNSServers.DNSServer -join ",")) {
                Set-HPEiLOIPv4NetworkSetting -Connection $iLOSession `
                                             -InterfaceType $InterfaceType `
                                             -DNSServerType $DNSServerTypes `
                                             -DNSServer $DNSServers
                $CurrentDNSServers = Get-HPEiLOIPv4NetworkSetting -Connection $iLOSession
            }

            If ($CurrentDNSServers.DomainName -ne $Zone) {
                Set-HPEiLOIPv4NetworkSetting -Connection $iLOSession -InterfaceType $InterfaceType -DomainName $Zone
            }

            ## Directory Settings
            $obj = Get-HPEiLODirectorySetting -Connection $iLOSession
            If (($obj.DirectoryServerAddress -ne $LDAPServer) -or ($obj.LDAPDirectoryAuthentication -notlike "*DefaultSchema") -or ($obj.GenericLDAPEnabled -ne "Yes") -or ($obj.LocalUserAccountEnabled -ne "Yes") -or ($obj.LOMObjectDN -ne $ldapUser) -or (-Not $obj.UserContext)) {
                Start-Sleep -Seconds 120 # Глюк ILO4 - если без паузы  -вылезаеь исключение
                Set-HPEiLODirectorySetting -Connection $iLOSession -LDAPDirectoryAuthentication Disabled -GenericLDAPEnabled No -LocalUserAccountEnabled Yes
                Set-HPEiLODirectorySetting -Connection $iLOSession -LDAPDirectoryAuthentication DirectoryDefaultSchema -GenericLDAPEnabled Yes -LocalUserAccountEnabled Yes
                If ((Get-HPEiLODirectorySetting -Connection $iLOSession).UserContext) {
                    Set-HPEiLODirectorySetting -Connection $iLOSession `
                    -LDAPDirectoryAuthentication DirectoryDefaultSchema `
                    -GenericLDAPEnabled Yes `
                    -LocalUserAccountEnabled Yes `
                    -LOMObjectDN $ldapUser `
                    -LOMObjectPassword $ldapPassword_PlainText `
                    -DirectoryServerAddress $LDAPServer `
                } else {
                    Set-HPEiLODirectorySetting -Connection $iLOSession `
                    -LDAPDirectoryAuthentication DirectoryDefaultSchema `
                    -GenericLDAPEnabled Yes `
                    -LocalUserAccountEnabled Yes `
                    -LOMObjectDN $ldapUser `
                    -LOMObjectPassword $ldapPassword_PlainText `
                    -DirectoryServerAddress $LDAPServer `
                    -UserContextIndex 1 `
                    -UserContext "@$Zone" `
                }            
            }
   
            ## Modify Access Groups
            # Get Access Groups
            $CurrentGroups = Get-HPEiLODirectoryGroup -Connection $iLOSession

            #Remove Groups other then Administrators,$grpName1\$grpsid1,$grpName2\$grpsid2
            $ForegnGroups = $CurrentGroups.GroupAccountInfo | ? {($_.GroupName -notlike "Administrators") -and (-Not (($_.GroupSID -eq $grpsid1) -and ($_.GroupName-eq $grpName1))) -and (-Not (($_.GroupSID -eq $grpsid2) -and ($_.GroupName-eq $grpName2)))}
            $ForegnGroups | % {
                Remove-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $_.GroupName | Out-Null
            }

            # Get Access Groups again after remove somewhat
            $CurrentGroups = Get-HPEiLODirectoryGroup -Connection $iLOSession
            #Add Groups and permissions for $grpsid1,$grpsid2 if not exists

            # ILO_USER_RW
            if (($CurrentGroups.GroupAccountInfo.GroupSID.Where{($_ -eq $grpsid1)}).Count -ne 1) { # Если группы нет - создаем
                If ($_.PN -like "*iLO 4*") {
                    Add-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName1 `
                                                                          -GroupSID $grpsid1 `
                                                                          -UserConfigPrivilege Yes `
                                                                          -RemoteConsolePrivilege Yes `
                                                                          -VirtualMediaPrivilege Yes `
                                                                          -iLOConfigPrivilege Yes `
                                                                          -LoginPrivilege Yes `
                                                                          -VirtualPowerAndResetPrivilege Yes
                } else {
                    Add-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName1 `
                                                                          -GroupSID $grpsid1 `
                                                                          -UserConfigPrivilege Yes `
                                                                          -RemoteConsolePrivilege Yes `
                                                                          -VirtualMediaPrivilege Yes `
                                                                          -iLOConfigPrivilege Yes `
                                                                          -LoginPrivilege Yes `
                                                                          -VirtualPowerAndResetPrivilege Yes `
                                                                          -HostBIOSConfigPrivilege Yes `
                                                                          -HostNICConfigPrivilege Yes `
                                                                          -HostStorageConfigPrivilege Yes
                                                                      
                    Set-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName1 -SystemRecoveryConfigPrivilege Yes -ea 0 -wa 0 | Out-Null
                }
            } else { # Если группа есть - проверяем права
                $Permissions = $CurrentGroups.GroupAccountInfo.Where{($_.GroupSID -eq $grpsid1)}
                $BadPermissions = $False
                (Get-Member -InputObject $Permissions[0] -MemberType Properties | ? {$_.Name -notlike "Group*"}).Name  | % { If ($Permissions[0].$_ -ne "Yes") { $BadPermissions = $True} }
                If ($BadPermissions) {
                    If ($_.PN -like "*iLO 4*") {
                        Set-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName1 `
                                                                            -GroupSID $grpsid1 `
                                                                            -UserConfigPrivilege Yes `
                                                                            -RemoteConsolePrivilege Yes `
                                                                            -VirtualMediaPrivilege Yes `
                                                                            -iLOConfigPrivilege Yes `
                                                                            -LoginPrivilege Yes `
                                                                            -VirtualPowerAndResetPrivilege Yes
                    } else {
                        Set-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName1 `
                                                                            -GroupSID $grpsid1 `
                                                                            -UserConfigPrivilege Yes `
                                                                            -RemoteConsolePrivilege Yes `
                                                                            -VirtualMediaPrivilege Yes `
                                                                            -iLOConfigPrivilege Yes `
                                                                            -LoginPrivilege Yes `
                                                                            -VirtualPowerAndResetPrivilege Yes `
                                                                            -HostBIOSConfigPrivilege Yes `
                                                                            -HostNICConfigPrivilege Yes `
                                                                            -HostStorageConfigPrivilege Yes
                                                                        
                        #Set-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName1 -SystemRecoveryConfigPrivilege Yes -ea 0 -wa 0 | Out-Null
                    }
                }
            }

            # ILO_USER_RO
            if (($CurrentGroups.GroupAccountInfo.GroupSID.Where{($_ -eq $grpsid2)}).Count -ne 1) { # Если группы нет - создаем
                If ($_.PN -like "*iLO 4*") {
                    Add-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName2 `
                                                                          -GroupSID $grpsid2 `
                                                                          -UserConfigPrivilege No `
                                                                          -RemoteConsolePrivilege No `
                                                                          -VirtualMediaPrivilege No `
                                                                          -iLOConfigPrivilege No `
                                                                          -LoginPrivilege Yes `
                                                                          -VirtualPowerAndResetPrivilege No
                } else {
                    Add-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName2 `
                                                                    -GroupSID $grpsid2 `
                                                                    -UserConfigPrivilege No `
                                                                    -RemoteConsolePrivilege No `
                                                                    -VirtualMediaPrivilege No `
                                                                    -iLOConfigPrivilege No `
                                                                    -LoginPrivilege Yes `
                                                                    -VirtualPowerAndResetPrivilege No `
                                                                    -HostBIOSConfigPrivilege No `
                                                                    -HostNICConfigPrivilege No `
                                                                    -HostStorageConfigPrivilege No `
                                                                    -SystemRecoveryConfigPrivilege No
                }
            } else { # Если группа есть - проверяем права
                $Permissions = $CurrentGroups.GroupAccountInfo.Where{($_.GroupSID -eq $grpsid2)}
                $BadPermissions = $False
                If ($Permissions[0].LoginPrivilege -eq "No") {$BadPermissions = $True}
                (Get-Member -InputObject $Permissions[0] -MemberType Properties | ? {($_.Name -notlike "Group*") -and ($_.Name -ne "LoginPrivilege")}).Name  | % { If ($Permissions[0].$_ -eq "Yes") { $BadPermissions = $True} }
                If ($BadPermissions) {
                    If ($_.PN -like "*iLO 4*") {
                        Set-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName2 `
                                                                        -GroupSID $grpsid2 `
                                                                        -UserConfigPrivilege No `
                                                                        -RemoteConsolePrivilege No `
                                                                        -VirtualMediaPrivilege No `
                                                                        -iLOConfigPrivilege No `
                                                                        -LoginPrivilege Yes `
                                                                        -VirtualPowerAndResetPrivilege No
                    } else {
                        Set-HPEiLODirectoryGroup -Connection $iLOSession -GroupName $grpName2 `
                                                                        -GroupSID $grpsid2 `
                                                                        -UserConfigPrivilege No `
                                                                        -RemoteConsolePrivilege No `
                                                                        -VirtualMediaPrivilege No `
                                                                        -iLOConfigPrivilege No `
                                                                        -LoginPrivilege Yes `
                                                                        -VirtualPowerAndResetPrivilege No `
                                                                        -HostBIOSConfigPrivilege No `
                                                                        -HostNICConfigPrivilege No `
                                                                        -HostStorageConfigPrivilege No `
                                                                        -SystemRecoveryConfigPrivilege No
                    }
                }
            }

            # Configure SNMPv1
            If ($_.PN -like "*iLO 5*") {
                If ((Get-HPEiLOSNMPAlertSetting -Connection $iLOSession).SNMPv1Enabled -ne "Enabled") { Set-HPEiLOSNMPAlertSetting -Connection $iLOSession -SNMPv1Enabled Enabled }            
            }
            If ((Get-HPEiLOSNMPSetting -Connection $iLOSession).ReadCommunity1 -ne "public") { Set-HPEiLOSNMPSetting -Connection $iLOSession -ReadCommunity1 public}

            ## Регистрация в DNS, если записи нет, если запись статическая, или текущее время >= timestamp+NoRefreshInterval+RefreshInterval-SafeDays
            $Hostname = (Get-HPEiLOIPv4NetworkSetting -Connection $iLOSession).DNSName
            If ($Hostname  -like "i-*") {$Hostname = $Hostname.Substring(2)}
            $DNSHostName = "i-$Hostname"
        
            $Hostname = $DNSHostName.TrimEnd(".domain.local")
            $SafeDays = 2 # for recreating record current datetime must be greater than timestamp+NoRefreshInterval+RefreshInterval-SafeDays ; SafeDays must be less then RefreshInterval

            Try { $iLODNSRecord = Get-DnsServerResourceRecord -Name $Hostname -ComputerName $DNSServer -ZoneName $Zone -ea 0 } catch {}

            If ($iLODNSRecord) { # If record exists
                if ($iLODNSRecord.Timestamp) { # If record has timestamp
                    if ((Get-Date) -ge (((((Get-DnsServerResourceRecord -Name $Hostname -ComputerName $DNSServer -ZoneName $Zone).Timestamp).AddDays((Get-DnsServerZoneAging -Name $Zone -ComputerName $DNSServer).NoRefreshInterval.Days)).AddDays((Get-DnsServerZoneAging -Name $Zone -ComputerName $DNSServer).RefreshInterval.Days)).AddDays((New-TimeSpan -Days -$SafeDays).Days))) { # If record timestame greater then NoRefreshInterval+RefreshInterval-SafeDays
                        RegisterDnsRecord
                    } else { # Timestamp less then NoRefreshInterval+RefreshInterval-SafeDays
                        Write-Host "The DNS record doesn't need to be recreated yet"
                    }
                } else { # Static record - must be recreated to dynamic
                    RegisterDnsRecord
                }
            } else { # Record absent - must be created
                RegisterDnsRecord
            }

            # Проверка SSL сертификата. Перевыпуск, если не проходит проверка или если срок действия истекает через 30 дней
            # https://www.sysadmins.lv/blog-en/how-to-add-fqdn-to-hp-ilo-request.aspx
            If (($iLOSession.TargetInfo.iLOGeneration).ToString() -eq "iLO4") { #iLO4
                $CertificateInfo = Get-HPEiLOSSLCertificateInfo -Connection $iLOSession -OutputType RawResponse # -OutputType RawResponse - костыль, вывод в бессруктурном виде т.к. iLO4 2.82 не может выдать в структурном
                
                If ($CertificateInfo.IndexOf(',"links"') -ne -1) {
                    $CertJSON = $($CertificateInfo.Substring($CertificateInfo.IndexOf('{"Issuer":'),($CertificateInfo.IndexOf(',"links"') - $CertificateInfo.IndexOf('{"Issuer":')))) | ConvertFrom-Json
                } else {
                    $CertJSON = "{" + ($CertificateInfo.Substring($CertificateInfo.IndexOf('{"Issuer":'))).Trim("{").Trim("}")+"}" | ConvertFrom-Json
                }

                #[datetime]$CertJSON.ValidNotAfter
                if (($CertJSON.Issuer -ne "DC = local, DC = merlion, CN = MLSubCA") -or ($CertJSON.Subject -notlike "*CN = $DNSHostName") -or ([datetime]$CertJSON.ValidNotAfter -lt (Get-Date).AddDays($(Get-Random -Maximum $CertExiredSafedays -Minimum $([int]$([math]::Round($CertExiredSafedays/3,0))))))) {
                    ReIssueCertificate
                } else {
                    Write-Host "The SSL certificate is valid and doesn't need to be reissued"
                }
            } else { #iLO5
                $CertificateInfo = Get-HPEiLOSSLCertificateInfo -Connection $iLOSession
                #$CertificateInfo.ValidNotAfter
                if (($CertificateInfo.Issuer -ne "DC = local, DC = merlion, CN = MLSubCA") -or ($CertificateInfo.Subject -notlike "*CN = $DNSHostName") -or ($CertificateInfo.ValidNotAfter -lt (Get-Date).AddDays($(Get-Random -Maximum $CertExiredSafedays -Minimum $([int]$([math]::Round($CertExiredSafedays/3,0)))))) -or ($_.ip -ne $CertificateInfo.ip) -or ($CertificateInfo.Subject.Substring($CertificateInfo.Subject.LastIndexOf("CN")).Replace("CN = ","") -ne $DNSHostName)) {
                    ReIssueCertificate
                } else {
                    Write-Host "The SSL certificate is valid and doesn't need to be reissued"
                }
            }
        }

        Disconnect-HPEiLO -Connection $iLOSession -ea 0 -wa 0
        $ProcessedServers += $_
    } else {Write-Host "iLO password not accepted"}
}

Write-Host "Processed Servers: $($ProcessedServers.Count)"
$iRecords = (Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone -RRType A | ? {($_.HostName -like "i-*") -and $_.TimeStamp}).HostName
Write-Host "i-* dynamic DNS records in zone: $($iRecords.Count)"

Write-Host "DNS records and Processed Servers comparison:"
Compare-Object -ReferenceObject $iRecords -DifferenceObject $($ProcessedServers.Hostname.replace(".domain.local","")) | Out-Host

If ($EnableLoggingMailing) {
    if ($(sls $LogfileFullpath -Pattern @("error","failed") -SimpleMatch)) {
        Send-MailMessage -SmtpServer $SMTPServer -Port 25 -From $SenderEmailAddress -To $RecivientsEmailAddress -Subject "iLO_SetParameters_DNS execution errors occured" -Body $((sls $LogfileFullpath -Pattern @("error","failed") -SimpleMatch -Context 1,0) -join "`r`n")
    }
    Stop-Transcript
}