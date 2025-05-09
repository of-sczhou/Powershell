### Password Get Utility
$AppVersion = "1.0.0.0"

[char[]]$StrArray1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
[char[]]$StrArray2 = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
[char[]]$StrArray3 = "1234567890".ToCharArray()
[char[]]$StrArray4 = ([char]"'" + '`-=~ !@#$%^&*()_+{}[]:";<>?,./|\').ToCharArray()

Do {
    Write-Host "Use default parameters? (Y/n): " -ForegroundColor Yellow -no
    $SkipCustomizations = Read-Host
    If (($SkipCustomizations.ToLower() -eq "y") -or ($SkipCustomizations -eq "")) {
        $PasswordLength = 16
        $NumPasswords = 5
        $RepeatMaxCount = 0
        $Weight1 = 0
        $Weight2 = 0
        $Weight3 = 0
        $Weight4 = 0
        $Exclusions = $null
        $NoErrors = $true
    } else {
        $NoErrors = $True #True if the password parameters are correctly defined
        Write-Host "Enter password length. Passwords must be at least 4 characters long. (Default 16): " -ForegroundColor Yellow -no
        $PasswordLength = Read-Host
        If (-Not $PasswordLength) {$PasswordLength = 16}

        Write-Host "Enter the number of passwords to be generated (Default 5): " -ForegroundColor Yellow -no
        $NumPasswords = Read-Host
        If (-Not $NumPasswords) {$NumPasswords = 5}

        Write-Host "Enter the allowed number of duplicate characters in the password (0): " -ForegroundColor Yellow -no
        $RepeatMaxCount = Read-Host
        If (-Not $RepeatMaxCount) {$RepeatMaxCount = 0}

        Write-Host "`nThe next parameters define weights of different types of characters in the password. If all weights are equal to zero, then all types of characters have the same weight." -ForegroundColor Cyan

        Write-Host "`nPassword must have at least # of uppercase letters A..Z in it. Default 0: " -ForegroundColor Yellow -no
        $Weight1 = Read-Host
        If (-Not $Weight1) {$Weight1 = 0}

        Write-Host "Password must have at least # of lowercase letters a..z in it. Default 0: " -ForegroundColor Yellow -no
        $Weight2 = Read-Host
        If (-Not $Weight2) {$Weight2 = 0}

        Write-Host "Password must have at least # of digits 0..9 in it. Default 0: " -ForegroundColor Yellow -no
        $Weight3 = Read-Host
        If (-Not $Weight3) {$Weight3 = 0}

        Write-Host "Password must have at least # of other symbols $($StrArray4 -join '') in it. Default 0: " -ForegroundColor Yellow -no
        $Weight4 = Read-Host
        If (-Not $Weight4) {$Weight4 = 0}

        Write-Host "Enter the characters you want to exclude from passwords: " -ForegroundColor Yellow -no
        $Exclusions = (Read-Host)
        If ($Exclusions) {$Exclusions = $Exclusions.ToCharArray()}

        If ($PasswordLength -lt 4) {Write-Host "Passwords must be at least 4 characters long" ; $NoErrors = $False}
        If (([int]$Weight1 + [int]$Weight2 + [int]$Weight3 + [int]$Weight4) -gt [int]$PasswordLength) {Write-Host ("The sum of weights exceeds the specified password length: " + $Weight1 + "+" + $Weight2 + "+" + $Weight3 + "+" + $Weight4 + " > " + $PasswordLength) ; $NoErrors = $False}
    }
} Until ($NoErrors)

################## Execution
if ($Exclusions) {
    1..4 | % {
        $Index = $_
        [char[]] $Matches = $null
        $Matches += (Get-Variable -Name StrArray$_).Value | ? {$Exclusions.IndexOf([char]$_) -ne -1}
        $Matches | % {(Get-Variable -Name StrArray$Index).Value = (((Get-Variable -Name StrArray$Index).Value -join "") -creplace "[$_]","").ToCharArray()}
    }
}

$StrBinValue = "1111"
if (($Weight1 + $Weight2 + $Weight3 + $Weight4) -eq 0) {$Weight1 = [math]::Floor($PasswordLength/4) ; $Weight2 = [math]::Floor($PasswordLength/4) ; $Weight3 = [math]::Floor($PasswordLength/4) ; $Weight4 = [math]::Floor($PasswordLength/4)} else {
        If ($Weight1 -eq 0) {$StrBinValue = $StrBinValue.Remove(0,1).Insert(0,"0")}
        If ($Weight2 -eq 0) {$StrBinValue = $StrBinValue.Remove(1,1).Insert(1,"0")}
        If ($Weight3 -eq 0) {$StrBinValue = $StrBinValue.Remove(2,1).Insert(2,"0")}
        If ($Weight4 -eq 0) {$StrBinValue = $StrBinValue.Remove(3,1).Insert(3,"0")}
}

Switch ($StrBinValue) {
    "0000" { $ResultingArray = $StrArray1 + $StrArray2 + $StrArray3 + $StrArray4 }
    "0001" { $ResultingArray = $StrArray4 }
    "0010" { $ResultingArray = $StrArray3}
    "0011" { $ResultingArray = $StrArray3 + $StrArray4 }
    "0100" { $ResultingArray = $StrArray2 }
    "0101" { $ResultingArray = $StrArray2 + $StrArray4 }
    "0110" { $ResultingArray = $StrArray2 + $StrArray3 }
    "0111" { $ResultingArray = $StrArray2 + $StrArray3 + $StrArray4 }
    "1000" { $ResultingArray = $StrArray1 }
    "1001" { $ResultingArray = $StrArray1 + $StrArray4 }
    "1010" { $ResultingArray = $StrArray1 + $StrArray3 }
    "1011" { $ResultingArray = $StrArray1 + $StrArray3 + $StrArray4 }
    "1100" { $ResultingArray = $StrArray1 + $StrArray2 + $StrArray3 + $StrArray4 }
    "1101" { $ResultingArray = $StrArray1 + $StrArray2 + $StrArray4 }
    "1110" { $ResultingArray = $StrArray1 + $StrArray2 + $StrArray3 }
    "1111" { $ResultingArray = $StrArray1 + $StrArray2 + $StrArray3 + $StrArray4 }
}
$RNDTopIndex = $ResultingArray.Length - 1

for ($j = 0 ; $j -le ($NumPasswords - 1); $j++) {
    Do {
        [char[]]$Password = $null
        for ($i = 0; $i -lt $PasswordLength; $i++) {
            If ($Password.Count -ne 0) {
                Do {
                    $RandomChar = $ResultingArray[(Get-Random -Maximum $RNDTopIndex)]
                } Until ((($RandomChar.Where({$Password -contains $_})).Count -le $RepeatMaxCount))
                $Password += $RandomChar
            } else {$Password += $ResultingArray[(Get-Random -Maximum $RNDTopIndex)]}
        }
        $PasswordQualityResult = $False
        Switch ($StrBinValue) {
            "0001" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray2 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray3 -contains $_})).Count -eq 0) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
            "0010" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray2 -eq 0})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -eq 0) }
            "0011" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray2 -ceq $_})).Count  -eq 0) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
            "0100" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -eq 0) -and (($Password.Where({$StrArray4 -contains $_})).Count -eq 0) }
            "0101" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -eq 0) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
            "0110" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -eq 0) }
            "0111" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
            "1000" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray3 -contains $_})).Count -eq 0) -and (($Password.Where({$StrArray4 -contains $_})).Count -eq 0) }
            "1001" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray3 -contains $_})).Count -eq 0) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
            "1010" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -eq 0) }
            "1011" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -eq 0) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
            "1100" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -eq 0) -and (($Password.Where({$StrArray4 -contains $_})).Count -eq 0) }
            "1101" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -eq 0) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
            "1110" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -eq 0) }
            "1111" { $PasswordQualityResult = (($Password.Where({$StrArray1 -ceq $_})).Count -ge $Weight1) -and (($Password.Where({$StrArray2 -ceq $_})).Count -ge $Weight2) -and (($Password.Where({$StrArray3 -contains $_})).Count -ge $Weight3) -and (($Password.Where({$StrArray4 -contains $_})).Count -ge $Weight4) }
        }
    } Until ($PasswordQualityResult)
    $Password -join ""
}
Pause

### Password Get Utility