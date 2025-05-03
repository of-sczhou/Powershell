Write-Host "https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=gpo" -fo 11
Write-Host "`nValidation of enabled VBS and memory integrity features:" -fo 14
$DeviceGuardState = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

Write-Host "`nAvailableSecurityProperties: enumerate and report state on the relevant security properties for VBS and memory integrity" -ForegroundColor Yellow
0..8 | % {
    If ($DeviceGuardState.AvailableSecurityProperties.IndexOf([UInt32]$_) -ne -1) {
        Switch ($_) {
            0 {Write-Host $_ -fo 12 -no; Write-Host " - no relevant properties exist on the device"}
            1 {Write-Host $_ -fo 10 -no; Write-Host " - hypervisor support is available"}
            2 {Write-Host $_ -fo 10 -no; Write-Host " - Secure Boot is available"}
            3 {Write-Host $_ -fo 10 -no; Write-Host " - DMA protection is available"}
            4 {Write-Host $_ -fo 10 -no; Write-Host " - Secure Memory Overwrite is available"}
            5 {Write-Host $_ -fo 10 -no; Write-Host " - NX protections are available"}
            6 {Write-Host $_ -fo 10 -no; Write-Host " - SMM mitigations are available"}
            7 {Write-Host $_ -fo 10 -no; Write-Host " - MBEC/GMET is available"}
            8 {Write-Host $_ -fo 10 -no; Write-Host " - APIC virtualization is available"}
        }
    } else {
        Switch ($_) {
            1 {Write-Host $_ -fo 12 -no; Write-Host " - hypervisor support is NOT available"}
            2 {Write-Host $_ -fo 12 -no; Write-Host " - Secure Boot is NOT available"}
            3 {Write-Host $_ -fo 12 -no; Write-Host " - DMA protection is NOT available"}
            4 {Write-Host $_ -fo 12 -no; Write-Host " - Secure Memory Overwrite is NOT available"}
            5 {Write-Host $_ -fo 12 -no; Write-Host " - NX protections are NOT available"}
            6 {Write-Host $_ -fo 12 -no; Write-Host " - SMM mitigations are NOT available"}
            7 {Write-Host $_ -fo 12 -no; Write-Host " - MBEC/GMET is NOT available"}
            8 {Write-Host $_ -fo 12 -no; Write-Host " - APIC virtualization is NOT available"}
        }
    }
}

Write-Host "`nCodeIntegrityPolicyEnforcementStatus: indicates the code integrity policy enforcement status" -fo 14
Switch ($DeviceGuardState.CodeIntegrityPolicyEnforcementStatus) {
    0 {Write-Host $_ -fo 12 -no; Write-Host " - OFF"}
    1 {Write-Host $_ -fo 11 -no; Write-Host " - Audit"}
    2 {Write-Host $_ -fo 10 -no; Write-Host " - Enforced"}
}

Write-Host  "`nRequiredSecurityProperties: describes the required security properties to enable VBS" -fo 14
$DeviceGuardState.RequiredSecurityProperties | % {
    Switch ($_) {
        0 {Write-Host "0 - Nothing is required"}
        1 {Write-Host "1 - hypervisor support is needed"}
        2 {Write-Host "2 - Secure Boot is needed"}
        3 {Write-Host "3 - DMA protection is needed"}
        4 {Write-Host "4 - Secure Memory Overwrite is needed"}
        5 {Write-Host "5 - NX protections are needed"}
        6 {Write-Host "6 - SMM mitigations are needed"}
        7 {Write-Host "7 - MBEC/GMET is needed"}
    }
}

Write-Host  "`nSecurityServicesConfigured: indicates whether Credential Guard or memory integrity is configured" -fo 14
0..7 | % {
    If ($DeviceGuardState.SecurityServicesConfigured.IndexOf([UInt32]$_) -ne -1) {
        Switch ($_) {
            0 {Write-Host $_ -fo 12 -no; Write-Host " - No services are configured"}
            1 {Write-Host $_ -fo 10 -no; Write-Host " - Credential Guard is configured"}
            2 {Write-Host $_ -fo 10 -no; Write-Host " - memory integrity is configured"}
            3 {Write-Host $_ -fo 10 -no; Write-Host " - System Guard Secure Launch is configured"}
            4 {Write-Host $_ -fo 10 -no; Write-Host " - SMM Firmware Measurement is configured"}
            5 {Write-Host $_ -fo 10 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is configured"}
            6 {Write-Host $_ -fo 10 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is configured in Audit mode"}
            7 {Write-Host $_ -fo 10 -no; Write-Host " - Hypervisor-Enforced Paging Translation is configured"}
        }
    } else {
        Switch ($_) {
            1 {Write-Host $_ -fo 12 -no; Write-Host " - Credential Guard is NOT configured"}
            2 {Write-Host $_ -fo 12 -no; Write-Host " - memory integrity is NOT configured"}
            3 {Write-Host $_ -fo 12 -no; Write-Host " - System Guard Secure Launch is NOT configured"}
            4 {Write-Host $_ -fo 12 -no; Write-Host " - SMM Firmware Measurement is NOT configured"}
            5 {Write-Host $_ -fo 12 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is NOT configured"}
            6 {Write-Host $_ -fo 12 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is NOT configured in Audit mode"}
            7 {Write-Host $_ -fo 12 -no; Write-Host " - Hypervisor-Enforced Paging Translation is NOT configurede"}
        }
    }
}

Write-Host  "`nSecurityServicesRunning: indicates whether Credential Guard or memory integrity is running" -fo 14
0..7 | % {
    If ($DeviceGuardState.SecurityServicesRunning.IndexOf([UInt32]$_) -ne -1) {
        Switch ($_) {
            0 {Write-Host $_ -fo 12 -no; Write-Host " - No services are running"}
            1 {Write-Host $_ -fo 10 -no; Write-Host " - Credential Guard is running"}
            2 {Write-Host $_ -fo 10 -no; Write-Host " - memory integrity is running"}
            3 {Write-Host $_ -fo 10 -no; Write-Host " - System Guard Secure Launch is running"}
            4 {Write-Host $_ -fo 10 -no; Write-Host " - SMM Firmware Measurement is running"}
            5 {Write-Host $_ -fo 10 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is running"}
            6 {Write-Host $_ -fo 10 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is running in Audit mode"}
            7 {Write-Host $_ -fo 10 -no; Write-Host " - Hypervisor-Enforced Paging Translation is running"}
        }
    } else {
        Switch ($_) {
            1 {Write-Host $_ -fo 12 -no; Write-Host " - Credential Guard is NOT running"}
            2 {Write-Host $_ -fo 12 -no; Write-Host " - memory integrity is NOT running"}
            3 {Write-Host $_ -fo 12 -no; Write-Host " - System Guard Secure Launch is NOT running"}
            4 {Write-Host $_ -fo 12 -no; Write-Host " - SMM Firmware Measurement is NOT running"}
            5 {Write-Host $_ -fo 12 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is NOT running"}
            6 {Write-Host $_ -fo 12 -no; Write-Host " - Kernel-mode Hardware-enforced Stack Protection is NOT running in Audit mode"}
            7 {Write-Host $_ -fo 12 -no; Write-Host " - Hypervisor-Enforced Paging Translation is NOT running"}
        }
    }
}

If ((Get-Member -InputObject $DeviceGuardState | ? {$_.MemberType -eq "Property"}).IndexOf("SmmIsolationLevel") -ne -1) {
    Write-Host "`nSmmIsolationLevel: indicates the SMM isolation level." -fo 14
    Write-Host $DeviceGuardState.SmmIsolationLevel
}

Write-Host "`nUsermodeCodeIntegrityPolicyEnforcementStatus: indicates the user mode code integrity policy enforcement status" -fo 14
Switch ($DeviceGuardState.UsermodeCodeIntegrityPolicyEnforcementStatus) {
    0 {Write-Host $_ -fo 12 -no; Write-Host " - OFF"}
    1 {Write-Host $_ -fo 11 -no; Write-Host " - Audit"}
    2 {Write-Host $_ -fo 12 -no; Write-Host " - Enforced"}
}

Write-Host "`nVirtualizationBasedSecurityStatus: indicates whether VBS is enabled and running" -fo 14
Switch ($DeviceGuardState.VirtualizationBasedSecurityStatus) {
    0 {Write-Host $_ -fo 12 -no; Write-Host " - VBS isn't enabled"}
    1 {Write-Host $_ -fo 11 -no; Write-Host " - VBS is enabled but not running"}
    2 {Write-Host $_ -fo 10 -no; Write-Host " - VBS is enabled and running"}
}

Write-Host "`nVirtualMachineIsolation: indicates whether virtual machine isolation is enabled" -fo 14
If ($DeviceGuardState.VirtualMachineIsolation) {Write-Host $DeviceGuardState.VirtualMachineIsolation $_ -fo 10} else {Write-Host $DeviceGuardState.VirtualMachineIsolation $_ -fo 12}

Write-Host "`nVirtualMachineIsolationProperties: indicates the set of virtual machine isolation properties that are available" -fo 14
Switch ($DeviceGuardState.VirtualMachineIsolationProperties) {
    0 {Write-Host $_ -fo 10 -no; Write-Host " - AMD SEV-SNP"}
    1 {Write-Host $_ -fo 10 -no; Write-Host " - Virtualization-based Security"}
    2 {Write-Host $_ -fo 10 -no; Write-Host " - Intel TDX"}
}