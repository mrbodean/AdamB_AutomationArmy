<#
.SYNOPSIS
    Confirm-CMClientHealth.ps1 checks for common issues encountered with the SCCM Client
.DESCRIPTION
    This script checks for common issues with the Configuration Manager Client.
    It will attempt to resolve some of the minor issues when the client is installed and running. 
    This script will not reinstall the client or repair WMI. 
    However the actions it does take require the script to be executed as SYSTEM or under an account with local administrator permissions.
.Example
    .\Confirm-CMClientHealth.ps1
.Example
    powershell -file Confirm-CMClientHealth.ps1
.Notes
    Created for Viega by Adam Bertram's Automation Army
    Author - Jon Warnken
#>
#Requires -RunAsAdministrator
$ComputerName = $env:COMPUTERNAME
$OSDriveFreeSpace = (Get-WmiObject -class Win32_LogicalDisk|Where-Object {$_.DeviceID -eq $env:SystemDrive}).FreeSpace
$OSDriveFreeSpace = [math]::Round($OSDriveFreeSpace/1GB,2)
$OSDriveFreeSpace = "$OSDriveFreeSpace GB"
$logfilepath = "C:\temp\SCCMClientHealth.log"
Function Start-log{
    [CmdletBinding()]
    param (
        [ValidateScript({ Split-Path $_ -Parent | Test-Path })]
        [string]$FilePath
    )
    try
    {
        if (!(Test-Path $FilePath))
    {
        ## Create the log file
        New-Item $FilePath -Type File | Out-Null
    }
        
    ## Set the global variable to be used as the FilePath for all subsequent Write-Log
    ## calls in this session
    $global:ScriptLogFilePath = $FilePath
    }
    catch
    {
        Write-Error $_.Exception.Message
    }
}
Function Write-log{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    Add-Content -Value $Line -Path $ScriptLogFilePath
}
Function Test-CMWMI {
        Try {
            Get-WmiObject -Namespace root/ccm -Class SMS_Client -ErrorAction Stop
            Write-Log -Message "$ComputerName WMI for Config Manager Client: OK"
            return $true
        } Catch {
            Write-Log -LogLevel 2 -Message "Failed Client WMI Check. Verifying General WMI Health. This will take a few minutes..."
            $WMIStatus = winmgmt /verifyrepository 
            If($WMIStatus -eq "WMI repository is consistent"){
                Write-Log -LogLevel 3 -Message "$ComputerName WMI for Config Manger Client: ERROR!! WMI is missing Client namespace. Reinstall Client!"
            }else{
                $WMIStatus
                Write-Log -LogLevel 3 -Message "$ComputerName WMI for Config Manger Client: ERROR!! Repair WMI and reinstall ConfigMgr client."
            }
            return $false
        }
    }
Function Reset-ProvisioningMode{
    $regpath = "HKLM:\SOFTWARE\Microsoft\CCM\CcmExec"
    $ProvisioningMode = (Get-ItemProperty -path $regpath).ProvisioningMode
    If($ProvisioningMode -eq "true"){
        Write-Log -LogLevel 2 -Message "$ComputerName is in Provisioning Mode! Remediating..."
        Invoke-wmiMethod -namespace root\CCM -class SMS_Client -Name SetClientProvisioningMode -ArgumentList $false|out-null
        return $false
    }else{
        Write-Log -Message "$ComputerName Provisioning Mode: OK"
        return $true
    }
}
Function Test-Service{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$service
    )
        $svc = get-service -Name $service
        if($svc){
            if($svc.Status -ne 'Running'){
                Write-Log -LogLevel 2 -Message "$svc is not running. Attempting to start"
                start-service -Name $svc
                Start-Sleep -Seconds 5
                if((get-service -Name $service).Status -eq 'Running'){
                    Write-Log -Message "$svc is running"
                    return $true
                }else{
                    Write-Log -LogLevel 3 -Message "Unable to start $svc"
                    return $false
                }
            }else{return $true}
        }else{
            Write-Log -LogLevel 3 -Message "$svc was not found! The client is not installed."
            return $false
        }
}
function Test-CCMCertificateError {
    # More checks to come
    $logFile1 = 'c:\windows\ccm\logs\ClientIDManagerStartup.log'
    $error1 = 'Failed to find the certificate in the store'
    $error2 = '[RegTask] - Server rejected registration 3'
    $content = Get-Content -Path $logFile1

    $ok = $true

    if ($content -match $error1) {
        $ok = $true
        Write-Log -LogLevel 2 -Message 'ConfigMgr Client Certificate: Error failed to find the certificate in store. Attempting fix.'
        Stop-Service -Name ccmexec -Force
        # Name is persistant across systems.
        $cert = 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\19c5cf9c7b5dc9de3e548adb70398402_50e417e0-e461-474b-96e2-077b80325612'
        Remove-Item -Path $cert -Force -ErrorAction SilentlyContinue | Out-Null
        # CCM create new certificate when missing.
        Start-Service -Name ccmexec
        # Delete the log file to avoid triggering this check again when it's fixed.
        Remove-Item $logFile -Force -ErrorAction SilentlyContinue | Out-Null
    }

    if ($content -match $error2) {
        $ok = $false
        Write-Log -LogLevel 3 -Message 'ConfigMgr Client Certificate: Error! Server rejected client registration. Client Certificate not valid. No auto-remediation.'
    }

    if ($ok = $true) {
        Write-Log -Message 'ConfigMgr Client Certificate: OK'
    }
    return $ok
}
Function Reset-UpdateStore {
    Write-Log -Message "Check StateMessage.log if State Messages are successfully forwarded to Management Point"
    $StateMessage = Get-Content -path "c:\Windows\CCM\Logs\StateMessage.log"
    if ($StateMessage -match "Successfully forwarded State Messages to the MP") {
        Write-Log -Message "$ComputerName StateMessage: OK" 
    }
    else { 
        Write-Log -LogLevel 2 -Message "$ComputerName StateMessage: ERROR. Remediating..."
        $SCCMUpdatesStore = New-Object -ComObject Microsoft.CCM.UpdatesStore
        $SCCMUpdatesStore.RefreshServerComplianceState()
        # Delete the log file to avoid triggering this check again when it's fixed.
        Remove-Item -Path "c:\Windows\CCM\Logs\StateMessage.log" -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
Function Test-RegistryPol {
    Write-Log -Message "Check WUAHandler.log if registry.pol need to be deleted"
    $WUAHandler = Get-Content -Path "c:\Windows\CCM\Logs\WUAHandler.log"
    if ($WUAHandler -contains "0x80004005") {

        Write-Log -LogLevel 2 -Message "$ComputerName GPO Cache: Error. Deleting registry.pol..."
        Remove-Item C:\Windows\System32\registry.pol -Force
        # Delete the log file to avoid triggering this check again when it's fixed.
        Remove-Item -Path "c:\Windows\CCM\Logs\WUAHandler.log" -Force -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Write-Log -Message "$ComputerName GPO Cache: OK"
    }
}

$ComputerName = $env:COMPUTERNAME
$OSDriveFreeSpace = (Get-WmiObject -class Win32_LogicalDisk|Where-Object {$_.DeviceID -eq $env:SystemDrive}).FreeSpace
$OSDriveFreeSpace = [math]::Round($OSDriveFreeSpace/1GB,2)
$OSDriveFreeSpace = "$OSDriveFreeSpace GB"
$logfilepath = "C:\temp\SCCMClientHealth.log"
Start-log -FilePath $logfilepath
Write-Log -Message "Starting Client Health Check on $ComputerName"
Write-Log -Message "$ComputerName has $OSDriveFreeSpace free on $($env:SystemDrive)"
If(!(Test-CMWMI)){
    Write-Log -LogLevel 3 -Message "No addtional checks will be made due to a WMI error"
    Write-Log -Message "-----------------------------------------------------------------"
    return
}
If(!(Reset-ProvisioningMode)){
    Write-Log -LogLevel 2 -Message "No addtional checks will be made due to the client being in Provisional Mode. The remidation for this will restart the ccm client and interupt addtional checks."
    Write-Log -Message "-----------------------------------------------------------------"
    return
}
If(!(Test-Service -service "ccmexec")){
    Write-Log -LogLevel 3 -Message "No addtional checks will be made because the SCCM client service was not found or could not be started."
    Write-Log -Message "-----------------------------------------------------------------"
    return
}
If(!(Test-CCMCertificateError)){
    Write-Log -LogLevel 3 -Message "No addtional checks will be made because the SCCM Client Certificate is invalid. Manually uninstall and remove client certificates before reinstalling. " 
    Write-Log -Message "-----------------------------------------------------------------"
    return
}
Reset-UpdateStore
Test-RegistryPol
Write-Log -Message "Completed Client Health Check on $ComputerName"
Write-Log -Message "-----------------------------------------------------------------"