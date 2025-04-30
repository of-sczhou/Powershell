# Получение перечня серверов, где в данный момент есть сессия указанной доменной УЗ + информация по Restricted Admin (есть ли билеты tgt от имени пользователя)
#Кого искать
$SearchSessionLike = "usersamaccountname"

#Где искать (указывать distinguishedName OU)
$SearchBase = "OU=Servers,DC=domainname,DC=domainroot"

#Показывать ли в результатах ошибки
$ShowErrors = $True

######################################################################################################################################################
$AllLiveWindowsSystems = Get-ADComputer -Filter * -SearchBase $SearchBase -SearchScope Subtree -Properties OperatingSystem,Description | ? {($_.OperatingSystem -like "*Windows*") -and ($_.OperatingSystem -like "*server*") -and $_.Enabled -and ($_.Description -ne "Failover cluster virtual network name account")} | Sort Name

$JobTimeLimitSec = 30 # Предельное время в секундах, отведенное на исполнение джоба $Worker, по истечении джоб принудительно останавливается

$Worker = {
    param($ComputerName,$SearchSessionLike,$hash,$Index)

    $hash[$Index] = (Get-Date).ToString('"StartDateTime-"yyyyMMdd-HHmmss')
    if (Resolve-DnsName $ComputerName -ea 0 -Type A) {
        if (((New-Object System.Net.Sockets.TcpClient).ConnectAsync($((Resolve-DnsName $ComputerName -ea Stop -Type A)[0].IPAddress),5985).Wait(999))) {
            Try {
                $InvokeResult = Invoke-Command -ComputerName $ComputerName -SessionOption $(New-PSSessionOption -NoMachineProfile) -ArgumentList $SearchSessionLike -ScriptBlock {
                    Param ($SearchSessionLike)
                    $quserResult = &cmd /c "quser $SearchSessionLike 2>&1"
                    If ($quserResult -notlike "error*") {
                        If ($quserResult -notlike "No User exists for*") {
                            $quserResult
                            [string[]]$KrbTickets = $()
                            (&cmd /c "%SYSTEMROOT%\System32\klist.exe sessions | findstr /i $SearchSessionLike") | % {
                                $KrbTickets += &cmd /c "%SYSTEMROOT%\System32\klist.exe tickets -li $($_.Split(" ")[3].Split(':').Replace('0x','')[1]) -lh $($_.Split(" ")[3].Split(':').Replace('0x','')[0])"
                            }
                            ($KrbTickets | sls krbtgt -SimpleMatch -Context 2,4).ForEach('ToString')
                        } else {"No User exists for"}
                    } else {"Error: unspecified"}
                } -ea Stop
                $hash[$Index] = $InvokeResult
            } catch {$hash[$Index] = "Error: $($_.FullyQualifiedErrorId)"}
        } else {$hash[$Index] = "Error: tcp:5985 connection failed"}
    } else {
        $hash[$Index] = "Error: unable to resolve DNS name"
    }
}

$MaxThreads = 7
#$InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
#$SessionState.ApartmentState = "STA"
#$SessionState.ThreadOptions = "Default"
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$RunspacePool.Open()

$Jobs = New-Object System.Collections.ArrayList

$ComputersArray = $AllLiveWindowsSystems.Name | Sort

$i=0
$hash = [hashtable]::Synchronized(@{})
Write-Host "`nНачало исполнения $(Get-Date)`n"
$ComputersArray | % {
    $PowerShellThread = [powershell]::Create()
    $PowerShellThread.RunspacePool = $RunspacePool
    $PowerShellThread.AddScript($Worker).AddArgument($_).AddArgument($SearchSessionLike).AddArgument($hash).AddArgument($i) | Out-Null
    $JobObj = New-Object -TypeName PSObject -Property @{
        Name = $_
        Handle = $PowerShellThread.BeginInvoke()
        Thread = $PowerShellThread
    }
    Write-Host $JobObj.Name
    $Jobs.Add($JobObj) | Out-Null
    $i++
}

while ($Jobs.Handle.IsCompleted -contains $false) {
    Write-Host ($Jobs.Handle.IsCompleted | ? {$_ -eq $False}).Count "running job remains"
    $Jobs | ? {$_.Handle.IsCompleted -eq $True} | % {
        $_.Thread.EndInvoke($_.Handle)
        $_.Thread.Dispose()
        $_.Thread = $Null
        $_.Handle = $Null
    }
    <#
    $Jobs | ? {($_.Handle.IsCompleted -eq $false) -and (((Get-date) - $((Get-Date) - [datetime]::parseexact($hash[$i], '"StartDateTime-"yyyyMMdd-HHmmss', $null))).TotalSeconds -ge $JobTimeLimitSec)} | % {
        "Forced stop of the job on $($_.Name)"
        $_.Thread.EndInvoke($_.Handle)
        $_.Thread.Dispose()
        $_.Thread = $Null
        $_.Handle = $Null
    }
    #>
    Start-Sleep -Milliseconds 1000
}

$RunspacePool.Close() | Out-Null
$RunspacePool.Dispose() | Out-Null

Write-Host "`nРезультаты по УЗ $SearchSessionLike на $(Get-Date)`n"

for ($i=0;$i -lt $ComputersArray.Count;$i++) {
    if ($hash[$i] -notlike "No User exists for*") {
        If ($ShowErrors) {
            If ($hash[$i] -like "Error: *") { Write-Host $ComputersArray[$i] -no -BackgroundColor Red -ForegroundColor White } else { Write-Host $ComputersArray[$i] -ForegroundColor Yellow }
            "`t$($hash[$i])"
        } else {
            If ($hash[$i] -notlike "Error: *") { Write-Host $ComputersArray[$i] -ForegroundColor Yellow ; "`t$($hash[$i])" }
        }
    }
}
######################################################################################################################################################