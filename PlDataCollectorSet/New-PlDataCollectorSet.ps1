Function New-PlDataCollectorSet {
    <#
        .SYNOPSIS
            Creates new data collector set from template on localhost or remote systems
 
        .DESCRIPTION
            Creates new data collector set from template on localhost or remote systems
 
        .PARAMETERS
            MANDATORY
            xmlTemplateName - name of XML Template file, default is first XML file in script folder

            OPTIONAL
            ComputerNames - single remote computer, array of remote computers, default is localhost
            SampleInterval - sets the system polling periodicity in seconds, default is 15 sec
            MaxFolderCount - set number of last collections to save on disk
            StartDataCollector - this is a switch parameter, if it present Data Collector Set start immediatly after creation

         .EXAMPLE
            New-PlDataCollectorSet : creates DCS on the local computer using the first template found in the script's startup folder (24hRot-3LastSegments.xml coming with script in original release folder)
            New-PlDataCollectorSet -DCSName "Perf_3Days_15Sec" -MaxFolderCount 3 -SampleInterval 15 -xmlTemplateName MyTemplate.xml -StartDataCollector
            New-PlDataCollectorSet -ComputerName "srv1.contoso.com","srv2.contoso.com" -Credential (Get-Credential)  -DCSName "Perf_3Days_15Sec" -MaxFolderCount 3 -SampleInterval 15 -xmlTemplateName  MyTemplate.xml -StartDataCollector

         .REMARKS
            If New Data Collector not starts at scheduled time it must be tuned according https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/user-defined-dcs-doesnt-run-as-scheduled
    #>

    [CmdletBinding()]
    param (
        [string[]]$ComputerName = @("localhost"),
        [parameter(ValueFromPipelineByPropertyName)][string]$DataCollectorName,
        [PSCredential]$Credential = $null,
        [string]$xmlTemplateName = ([string[]](Get-ChildItem -Path "$(if (-Not (Get-Variable psISE -ea 0)) {$MyInvocation.MyCommand.Path.Substring(0,$($MyInvocation.MyCommand.Path.LastIndexOf("\")))} else {$psISE.CurrentFile.FullPath.Substring(0,$($psISE.CurrentFile.FullPath.LastIndexOf("\")))})\" -Filter "*.xml").FullName)[0],
        [parameter(ValueFromPipelineByPropertyName)][int]$SampleInterval,
        [parameter(ValueFromPipelineByPropertyName)][int]$MaxFolderCount,
        [switch]$StartDataCollector,
        [parameter(ValueFromPipelineByPropertyName,DontShow)][xml]$XML
    )

    begin {
        [xml]$xmlTemplate = Get-Content -Path $xmlTemplateName
        $SessionOptions = New-PSSessionOption -NoMachineProfile -SkipCACheck

        $Action = {
            param( $DataCollectorName, $xml, $Sample, $MaxFolderCount, $StartDC )

            # Customize template by removing some computer-specific nodes or edit nodes with new values according incoming parameters if they are presents
            "//LatestOutputLocation","//OutputLocation","//Security" | % { try {$xml.ChildNodes.SelectNodes($_) | % {$_.ParentNode.RemoveChild($_)}} catch {} }
            if ($DataCollectorName -ne "") {
                $xml.SelectSingleNode("//Name").'#text' = $DataCollectorName
                $RootPathNode = $xml.SelectSingleNode("//RootPath")
                $RootPathNode.'#text' = $RootPathNode.'#text'.Substring(0,$RootPathNode.'#text'.LastIndexOf("\") + 1) + $DataCollectorName
            } else {$DataCollectorName = $xml.SelectSingleNode("//Name").'#text'}

            $Description = "Created by $env:USERNAME@$env:USERDOMAIN at $((Get-Date).ToString("yyyy.MM.dd-HH:mm:ss"))"
            $xml.SelectSingleNode("//Description").'#text' = $Description
            $xml.SelectSingleNode("//DescriptionUnresolved").'#text' = $Description
            
            if ($Sample -ne "") { $xml.SelectSingleNode("//SampleInterval").'#text' = [string]$Sample }

            if ($MaxFolderCount -ne "") { $xml.SelectSingleNode("//MaxFolderCount").'#text' = [string]$MaxFolderCount }

            $xml.SelectSingleNode("//StartDate").'#text' = "$((Get-Date).Month.ToString())/$((Get-Date).Day.ToString())/$((Get-Date).Year.ToString())"

            # Rewrite values of 'CounterDisplayName' nodes with target OS System Language Names
            $ENU = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009" -Name "Counter").Counter
            $Current = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" -Name "Counter").Counter

            $i = 0
            $xml.SelectNodes("//Counter") | % {
                $CounterFull = $_.'#text'.split("\")
                if ($CounterFull[1].IndexOf("(") -ne -1) {
                    $Brackets = $CounterFull[1].Substring($CounterFull[1].IndexOf("("))
                    $CounterPart1 = $CounterFull[1].Replace($Brackets,"")
                } else {
                    $Brackets = ""
                    $CounterPart1 = $CounterFull[1]
                }
    
                $Part1Index = $ENU[$ENU.IndexOf($CounterPart1) - 1]
                $Part1CurrentLanguage = $Current[$Current.IndexOf($Part1Index) + 1] + $Brackets
                if ($CounterFull[2] -eq "*") {
                    $Part2CurrentLanguage = $CounterFull[2]
                } else {
                    $Part2Index = $ENU[$ENU.IndexOf($CounterFull[2]) - 1]
                    $Part2CurrentLanguage = $Current[$Current.IndexOf($Part2Index) + 1]
                }
    
                ($xml.SelectNodes("//CounterDisplayName"))[$i].innertext = $("\" + $Part1CurrentLanguage + "\" + $Part2CurrentLanguage)
                $i++
            }

            $datacollectorset = New-Object -COM Pla.DataCollectorSet
            $datacollectorset.SetXml($xml.OuterXml)

            # Check is Data Collector Set already exist
            $schedule = New-Object -ComObject "Schedule.Service"
            $schedule.Connect()
            $folder = $schedule.GetFolder("Microsoft\Windows\PLA")
            $tasks = @()
            $tasknumber = 0
            $done = $false
            do {
                try {
                    $task = $folder.GetTasks($tasknumber)
                    $tasknumber++
                    if ($task) {
                        $tasks += $task
                    }
                }
                catch {
                    $done = $true
                }
            }
            while (-Not $done)
            $null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($schedule)

            $DataCollectorName = $xml.SelectSingleNode("//Name").'#text'
            if ($tasks | ? {$_.Name -eq $DataCollectorName}) {
                if ($(Read-Host "$DataCollectorName already exist, do you want to overwrite it (y/n)") -eq "y") {
                    logman stop -n $DataCollectorName
                    $sets = New-Object -ComObject Pla.DataCollectorSet
                    $sets.Query($DataCollectorName, $null)
                    $set = $sets.PSObject.Copy()
                    Remove-Item -Path $set.RootPath -Recurse -Force -ErrorAction SilentlyContinue
                    logman delete -n $DataCollectorName

                    $datacollectorset.Commit($DataCollectorName , $null , 0x0003) | Out-Null
                    if ($StartDC) {$datacollectorset.Start($true)}
                } else {"Skip Actions" | Out-Host}
            } else {
                $datacollectorset.Commit($DataCollectorName , $null , 0x0003) | Out-Null
                if ($StartDC) {$datacollectorset.Start($true)}
            }

            Get-ScheduledTask -TaskName $DataCollectorName | Select @{name='Computername';exp={$env:COMPUTERNAME}},TaskName,State,@{name='NextRunTime';exp={(Get-ScheduledTask -TaskName $_.TaskName | Get-ScheduledTaskInfo).NextRunTime}} | ft -AutoSize
        }
    }

    Process {
        Try {
            if ($ComputerName -ne @("localhost")) { #Remote Computer
                If ($Credential) {
                    $ComputerName | % {
                        $_
                        Invoke-Command -Credential $Credential -ComputerName $_ -SessionOption $SessionOptions -ArgumentList ($DataCollectorName,$xmlTemplate,$SampleInterval,$MaxFolderCount,$($StartDataCollector.IsPresent)) -ScriptBlock $Action
                    }
                } else {
                    $ComputerName | % {
                        Invoke-Command -ComputerName $_ -SessionOption $SessionOptions -ArgumentList ($DataCollectorName,$xmlTemplate,$SampleInterval,$MaxFolderCount,$($StartDataCollector.IsPresent)) -ScriptBlock $Action
                    }
                }
            } else { #localhost
                Invoke-Command -ArgumentList ($DataCollectorName,$xmlTemplate,$SampleInterval,$MaxFolderCount,$($StartDataCollector.IsPresent)) -ScriptBlock $Action
            }
            Write-Host "Done"
        } catch {$_.Message}
    }
}

Register-ArgumentCompleter -CommandName New-PlDataCollectorSet -ParameterName xmlTemplateName -ScriptBlock {[string[]](Get-ChildItem -Path "$(if (-Not (Get-Variable psISE -ea 0)) {$MyInvocation.MyCommand.Path.Substring(0,$($MyInvocation.MyCommand.Path.LastIndexOf("\")))} else {$psISE.CurrentFile.FullPath.Substring(0,$($psISE.CurrentFile.FullPath.LastIndexOf("\")))})\" -Filter "*.xml").FullName}