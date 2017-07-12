<#
isclientinstalled
    service 
        Present
        Running 
        Start (if needed)
getclientversion
testccmcert
getpendingreboot
registrypol 
#>
#Requires -RunAsAdministrator

Start-log{
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
Write-log{
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
            Write-Log -Message "$ComputerName) WMI for Config Manager Client: OK"
            return = $true
        } Catch {
            Write-Log -LogLevel 2 -Message "Failed Client WMI Check. Verifying General WMI Health. This will take a few minutes..."
            $WMIStatus = winmgmt /verifyrepository 
            If($WMIStatus -eq "WMI repository is consistent"){
                Write-Log -LogLevel 3 -Message "$($env:ComputerName) WMI for Config Manger Client: ERROR!! WMI is missing Client namespace. Reinstall Client!"
            }else{
                $WMIStatus
                Write-Log -LogLevel 3 -Message "$($env:ComputerName) WMI for Config Manger Client: ERROR!! Repair WMI and reinstall ConfigMgr client."
            }
            return = $false
        }
    }
Function Reset-ProvisioningMode{
    $regpath = "HKLM:\SOFTWARE\Microsoft\CCM\CcmExec"
    $ProvisioningMode = (Get-ItemProperty -path $regpath).ProvisioningMode
    If($ProvisioningMode -eq "true"){
        Write-Log -LogLevel 2 -Message "$($env:ComputerName) is in Provisioning Mode! Remediating..."
        Invoke-wmiMethod -namespace root\CCM -class SMS_Client -Name SetClientProvisioningMode -ArgumentList $false|out-null
        return $false
    }else{
        Write-Log -Message "$($env:ComputerName) Provisioning Mode: OK"
        return $true
    }
}
Function Test-Service{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$service
    )
        $svc = get-service -Name $svc
}

$ccmservice = Get-Service -Name CcmExec -ErrorAction SilentlyContinue

$ComputerName = $env:COMPUTERNAME
$OSDriveFreeSpace = (Get-WmiObject -class Win32_LogicalDisk|Where-Object {$_.DeviceID -eq $env:SystemDrive}).FreeSpace
$OSDriveFreeSpace = [math]::Round($OSDriveFreeSpace/1GB,2)
$OSDriveFreeSpace = "$OSDriveFreeSpace GB"
Start-log -FilePath "$($Env:SystemDrive)\TEMP\$($MyInvocation.ScriptName)"
Write-Log -Message "Starting $($MyInvocation.ScriptName) on $ComputerName"
Write-Log -Message "$ComputerName has $OSDriveFreeSpace free on $($env:SystemDrive)"
If(!(Test-CMWMI)){
    Write-Log -LogLevel 3 -Message "No addtional checks will be made due to a WMI error" 
}
If(!(Reset-ProvisioningMode)){
    Write-Log -LogLevel 2 -Message "No addtional checks will be made due to the client being in Provisional Mode. The remidation for this will restart the ccm client and interupt addtional checks." 
}

