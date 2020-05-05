$existingModules = @((Get-Module).Name) # Save existing modules
$existingVars = @((Get-Variable -Scope Global).Name) # Save existing variables, put first in any script
######################################

$Error.Clear() # Fresh start!
$scriptName = "Get-KempStatus.ps1"
$eventId = 18003
$isDebugging = $false

[string] $kempUser = "$RunAs[Name='CO.Kemp.KempRunasProfile']/UserName$" # Not sure if you can do this, lets try
[string] $kempPass = "$RunAs[Name='CO.Kemp.KempRunasProfile']/Password$" # Not sure if you can do this, lets try


# Create SCOM API Object
$scomAPI = New-Object -comObject 'MOM.ScriptAPI'

$knownDebugHosts = @(
    "Visual Studio Code Host"
    "Windows PowerShell ISE Host"
)
if ($host.Name -in $knownDebugHosts) {
    # script is running in a known debug environment, set debug values
    $tempDir = "$env:TEMP\CO.Kemp"
    
	# needed a slightly more secure way to debug these scripts
	# using serialized credentials (encrypted) from file
	# if file is missing, script will ask for credentials, and save them for later use
	$credPath = $tempDir + "\kempcreds.xml"
    if (Test-Path -Path $credPath) {
        $credentials = Import-Clixml -Path $credPath
    } else {
        $credentials = Get-Credential -Message "Enter Kemp Login"
        Export-Clixml -Path $credPath -InputObject $credentials
    }
    
    [string] $kempUser = $credentials.UserName
    [string] $kempPass = $credentials.GetNetworkCredential().Password
    $LoadMasterBaseUrls = @("https://avmk01.westeurope.cloudapp.azure.com:8443/") #my free tier azure appliance, perfect for development, may be offline
    if (!(Test-Path -Path $tempDir)) {New-Item -Path $tempDir -ItemType Directory}
    $isDebugging = $true
}
else {
    # Get all LoadMaster instances and their base urls
    $lmClass = Get-SCOMClass -Name "CO.Kemp.LoadMaster"
    $lmInstances = Get-SCOMClassInstance -Class $lmClass
    [string[]] $LoadMasterBaseUrls = $lmInstances.'[CO.Kemp.LoadMaster].managementurl'
}

$scomAPI.LogScriptEvent($scriptName, $eventId, 0, "`nScript probe started by $(whoami) in `"$($host.Name)`".`nLoadMasterBaseUrls = $($LoadMasterBaseUrls -join ",")`nDebug=$($isDebugging)")

$logString = "`n"

#region KempClass
class Kemp {
    # Kemp Base URL (LoadMaster admin adress?)
    [string] $AdminAdress
    [System.Net.NetworkCredential] $Credential
    [System.Xml.XmlElement] $StatsXml

    [hashtable] GetClusters() {
        $clResult = $this.QueryKempApi("access/listclusters", @{}).Response.Success.Data

        #$clResult.InnerXml | Out-File -FilePath ".\cl.xml"
        $cl = @{}
        foreach ($clXml in $clResult) {

        }

        return $cl
    }

    [hashtable] GetAll() {
        $allResult = $this.QueryKempApi("access/getall", @{}).Response.Success.Data

        #$allResult.InnerXml | Out-File -FilePath ".\all.xml"
        $all = @{}
        foreach ($allXml in $allResult.ChildNodes) {
            #TODO Add $cl.Add() for cluster hashtag
            if ($allXml.Name -in $all.Keys) {
                $all[$allXml.Name] = $all[$allXml.Name] + "," + $allXml.InnerText
            }
            else {
                $all.Add($allXml.Name, $allXml.InnerText) | Out-Null
            }
        }
        if ($all.Count -gt 1) {
            #got results, add proper management property
            $all.Add("managementhost", $(([System.Uri]$this.AdminAdress).Host)) | Out-Null
        }
        return $all
    }

    [System.Xml.XmlElement] LoadStatsXML() {
        # using this member to avoid multiple API-checks when data is already loaded
        if ($null -eq $this.StatsXml) {
            #TODO: Need better StatsXML check
            $statsResult = $this.QueryKempApi("access/stats", @{}).Response.Success.Data
            #$statsResult.InnerXml | Out-File -FilePath ".\stats.xml" -Force
            $this.StatsXml = $statsResult
        }
        return $this.StatsXml
    }

    [hashtable] GetVSStats() {
        $xml = $this.LoadStatsXML()
        
        $vsStats = @{}
        foreach ($vsStatsXml in $xml.SelectNodes("//Vs")) {
            $properties = @{}
            foreach ($propertyXml in $vsStatsXML.ChildNodes) {
                $properties[$propertyXML.Name] = $propertyXml.InnerText
            }
            $vsStats[$vsStatsXml.Index] = $properties
        }
        if ($vsStats.Count -gt 1) {
            #got results, add proper management property
            $vsStats.Add("managementhost", $(([System.Uri]$this.AdminAdress).Host)) | Out-Null
        }
        return $vsStats
    }

    [hashtable] GetRSStats() {
        $xml = $this.LoadStatsXML()
        
        $rsStats = @{}
        foreach ($rsStatsXml in $xml.SelectNodes("//Rs")) {
            $properties = @{}
            foreach ($propertyXml in $rsStatsXML.ChildNodes) {
                $properties[$propertyXML.Name] = $propertyXml.InnerText
            }
            $rsStats[$rsStatsXml.RsIndex] = $properties
        }
        if ($rsStats.Count -gt 1) {
            #got results, add proper management property
            $rsStats.Add("managementhost", $(([System.Uri]$this.AdminAdress).Host)) | Out-Null
        }
        return $rsStats
    }

    [hashtable] GetLMStats() {
        $xml = $this.LoadStatsXML()
        
        $lmStats = @{}
        $lmStats["managementhost"] = $(([System.Uri]$this.AdminAdress).Host)
        $lmStats["CPU_SystemTotal"] = $xml.CPU.total.System
        $lmStats["MEM_used"] = $xml.Memory.memused
        $lmStats["MEM_usedPct"] = $xml.Memory.percentmemused
        $lmStats["MEM_free"] = $xml.Memory.memfree
        $lmStats["MEM_freePct"] = $xml.Memory.percentmemfree
        $lmStats["VSTotals_ConnsPerSec"] = $xml.VStotals.ConnsPerSec
        $lmStats["VSTotals_BitsPerSec"] = $xml.VStotals.BitsPerSec
        $lmStats["VSTotals_BytesPerSec"] = $xml.VStotals.BytesPerSec
        $lmStats["VSTotals_PktsPerSec"] = $xml.VStotals.PktsPerSec
        return $lmStats
    }

    [hashtable] ListFQDNs() {
        $allResult = $this.QueryKempApi("access/listfqdns", @{}).Response.Success.Data

        #$allResult.InnerXml | Out-File -FilePath ".\all.xml"
        $all = @{}
        foreach ($allXml in $allResult.ChildNodes) {
            #TODO Add $cl.Add() for cluster hashtag
            if ($allXml.Name -in $all.Keys) {
                $all[$allXml.Name] = $all[$allXml.Name] + "," + $allXml.InnerText
            }
            else {
                $all.Add($allXml.Name, $allXml.InnerText) | Out-Null
            }
        }

        return $all
    }

    [hashtable] ListIPs() {
        $allResult = $this.QueryKempApi("access/listips", @{}).Response.Success.Data

        #$allResult.InnerXml | Out-File -FilePath ".\all.xml"
        $all = @{}
        foreach ($allXml in $allResult.ChildNodes) {
            #TODO Add $cl.Add() for cluster hashtag
            if ($allXml.Name -in $all.Keys) {
                $all[$allXml.Name] = $all[$allXml.Name] + "," + $allXml.InnerText
            }
            else {
                $all.Add($allXml.Name, $allXml.InnerText) | Out-Null
            }
        }

        return $all
    }

    [Hashtable] GetRealServers() {
        $rsResult = $this.QueryKempApi("access/listvs", @{}).Response.Success.Data
        $rs = @{}
        foreach ($rsXml in $rsResult.SelectNodes("//Rs")) {
            $rs.Add($rsXml.RsIndex, @{
                    "Status"   = $rsXml.Status
                    "VSIndex"  = $rsXml.VSIndex
                    "RsIndex"  = $rsXml.RsIndex
                    "Addr"     = $rsXml.Addr
                    "Port"     = $rsXml.Port
                    "DnsName"  = $rsXml.DnsName
                    "Forward"  = $rsXml.Forward
                    "Weight"   = $rsXml.Weight
                    "Limit"    = $rsXml.Limit
                    "Follow"   = $rsXml.Follow
                    "Enable"   = $rsXml.Enable
                    "Critical" = $rsXml.Critical
                }
            ) | Out-Null
        }

        return $rs
    }
    
    [Hashtable] GetVirtualServices() {
        $vsResult = $this.QueryKempApi("access/listvs", @{}).Response.Success.Data
        $vs = @{}
        foreach ($vsXml in $vsResult.VS) {
            $vs.Add($vsXml.Index, @{
                    "VSAddress"            = $vsXml.VSAddress
                    "AddVia"               = $vsXml.AddVia
                    "CheckUse1.1"          = $vsXml.'CheckUse1.1'
                    "RsMinimum"            = $vsXml.RsMinimum
                    "SSLReverse"           = $vsXml.SSLReverse
                    "Layer"                = $vsXml.Layer
                    "MasterVS"             = $vsXml.MasterVS
                    "ServerInit"           = $vsXml.ServerInit
                    "Protocol"             = $vsXml.Protocol
                    "NeedHostName"         = $vsXml.NeedHostName
                    "CheckUseGet"          = $vsXml.CheckUseGet
                    "Compress"             = $vsXml.Compress
                    "AlertThreshold"       = $vsXml.AlertThreshold
                    "NPreProcessRules"     = $vsXml.NPreProcessRules
                    "Index"                = $vsXml.Index
                    "NumberOfRSs"          = $vsXml.NumberOfRSs
                    "ErrorCode"            = $vsXml.ErrorCode
                    "PS"                   = $vsXml.PS
                    "NickName"             = $vsXml.NickName
                    "SSLRewrite"           = $vsXml.SSLRewrite
                    "EspEnabled"           = $vsXml.EspEnabled
                    "Idletime"             = $vsXml.Idletime
                    "IsTransparent"        = $vsXml.IsTransparent
                    "Enable"               = $vsXml.Enable
                    "InputAuthMode"        = $vsXml.InputAuthMode
                    "TlsType"              = $vsXml.TlsType
                    "QoS"                  = $vsXml.QoS
                    "ForceL7"              = $vsXml.ForceL7
                    "MatchLen"             = $vsXml.MatchLen
                    "CheckPort"            = $vsXml.CheckPort
                    "Verify"               = $vsXml.Verify
                    "CheckType"            = $vsXml.CheckType
                    "ForceL4"              = $vsXml.ForceL4
                    "VStype"               = $vsXml.VStype
                    "MultiConnect"         = $vsXml.MultiConnect
                    "Transparent"          = $vsXml.Transparent
                    "InterceptOpts"        = $vsXml.InterceptOpts.Opt
                    "Schedule"             = $vsXml.Schedule
                    "Status"               = $vsXml.Status
                    "EnhancedHealthChecks" = $vsXml.EnhancedHealthChecks
                    "CheckUrl"             = $vsXml.CheckUrl
                    "NResponseRules"       = $vsXml.NResponseRules
                    "Transactionlimit"     = $vsXml.Transactionlimit
                    "SSLReencrypt"         = $vsXml.SSLReencrypt
                    "MasterVSID"           = $vsXml.MasterVSID
                    "SubnetOriginating"    = $vsXml.SubnetOriginating
                    "VSPort"               = $vsXml.VSPort
                    "PersistTimeout"       = $vsXml.PersistTimeout
                    "NRequestRules"        = $vsXml.NRequestRules
                    "FollowVSID"           = $vsXml.FollowVSID
                    "Persist"              = $vsXml.Persist
                    "OutputAuthMode"       = $vsXml.OutputAuthMode
                    "NRules"               = $vsXml.NRules
                    "StartTLSMode"         = $vsXml.StartTLSMode
                    "OCSPVerify"           = $vsXml.OCSPVerify
                    "UseforSnat"           = $vsXml.UseforSnat
                    "Intercept"            = $vsXml.Intercept
                    "Cache"                = $vsXml.Cache
                    "ClientCert"           = $vsXml.ClientCert
                }
            ) | Out-Null
        }
        return ($vs)
    }

    # Constructor 
    Kemp ([string] $AdminAdress, [string] $Username, [securestring] $Password) {
        $this.AdminAdress = $AdminAdress.TrimEnd("/")

        $creds = [System.Net.NetworkCredential]::new($username, $Password)
        $this.Credential = $creds
    }

    # ToJson
    [string] ToJson () {
        return (ConvertTo-Json -InputObject $this)
    }

    hidden [Xml] QueryKempApi($Url, [Hashtable]$Parameters) {
        $Arr = @()

        foreach ($Key in $Parameters.Keys) {
            $Arr += "$Key=$($Parameters[$Key])"
        }

        $ParamStr = [string]::Join("&", $Arr)
        if ($ParamStr.Length -gt 0) {
            $Url = "$($Url)?$($ParamStr)"
        }

        [System.Net.ServicePointManager]::Expect100Continue = $true
        [System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #DevSkim: ignore DS126185 
        [System.Net.ServicePointManager]::SecurityProtocol = 'Tls11', 'Tls12'

        $Request = [System.Net.HttpWebRequest]::Create("$(($this.AdminAdress))/$Url")
        $Request.Credentials = ($this.Credential)

        $Response = $Request.GetResponse()
        $Stream = $response.GetResponseStream()

        $Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
        $Reader = New-Object system.io.StreamReader($Stream, $Encoding)
        $Result = $Reader.ReadToEnd()

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        return [Xml]$Result
    }

    hidden [Boolean] ValidateUrl($Url) {
        if (!$Url.StartsWith("https://")) {
            return $false
        }
    
        return $true
    }
}
#endregion KempClass

function Send-PropertyBag {
    param (
        [System.Collections.ArrayList] $Properties
		,[bool] $Debug
    )

    $omApi = New-Object -ComObject "MOM.ScriptApi"
    foreach($propertyHT in $Properties) {
        $pb = $omApi.CreatePropertyBag()
        foreach ($key in $propertyHT.Keys) {
            $pb.AddValue($key, $propertyHT[$key])
        }

        if ($Debug) {
            $omApi.AddItem($pb)
        }
        else {
            $pb
        }
    }
    if ($Debug) {
        $omApi.ReturnItems()
		$scomAPI.LogScriptEvent($scriptName, $eventId, 0, "`nTHIS EVENT IS ONLY IN DEBUG!!!")
    }
}

$pbHTArray = New-Object -TypeName System.Collections.ArrayList

foreach ($url in $LoadMasterBaseUrls) {
    $error.Clear()
    $username = $kempUser
    $password = ConvertTo-SecureString -String $kempPass -AsPlainText -Force

    $kemp = [Kemp]::new($url, $username, $password)

    $kemp.ValidateUrl($kemp.AdminAdress)

    $logString += "Connecting to $url"

    try {
        $vsHt = $kemp.GetVirtualServices() #VirtualService (incl. SubVS) information
        $rsHt = $kemp.GetRealServers() # RealServer information
        $allHt = $kemp.GetAll() # This is where you get LoadMaster node information
        $vsStatsHt = $kemp.GetVSStats()
        $rsStatsHt = $kemp.GetRSStats()
        $lmStatsHt = $kemp.GetLMStats()
        # Cluster API is not accessible unless you're admin, we'll deal with that later
        #$clHt = $kemp.GetClusters() 
    }
    catch {
        Continue
    }


    # Saving to disk, only for manual analysis during development
    if ($isDebugging) {
        $vsHt | ConvertTo-Json | Out-File -FilePath "$tempDir\vs.json"
        $rsHt | ConvertTo-Json | Out-File -FilePath "$tempDir\rs.json"
        $allHt | ConvertTo-Json | Out-File -FilePath "$tempDir\all.json"
        $vsStatsHt | ConvertTo-Json | Out-File -FilePath "$tempDir\vsStatsHt.json"
        $rsStatsHt | ConvertTo-Json | Out-File -FilePath "$tempDir\rsStatsHt.json"
        $lmStatsHt | ConvertTo-Json | Out-File -FilePath "$tempDir\lmStatsHt.json"
        # Cluster API is not accessible unless you're admin, we'll deal with that later
        #$clHt | ConvertTo-Json | Out-File -FilePath "$($env:TEMP)\cl.json"
    }

    if ($allHt.Count -gt 0) {
        # got data in allHT, which means there's a LoadMaster returned.

        [string] $identifier = $allHt.managementhost

        if (($allHt.ha1hostname.Length -gt 0) -and ($allHt.hostname -eq $allHt.ha1hostname)) {
            # ha1 is active
            $ha1Active = 1
            $ha2Active = 0
        } elseif (($allHt.ha2hostname.Length -gt 0) -and ($allHt.hostname -eq $allHt.ha2hostname)) {
            # ha2 is active
            $ha1Active = 0
            $ha2Active = 1
        } else {
            # not a cluster
            $ha1Active = 0
            $ha2Active = 0
        }

        # Create LM Propertybag
        $pbHTArray.Add(@{
            "objecttype" = "lm"
            "hostname"   = $allHt.managementhost
            "responds"   = "yes"
            "identifier" = $identifier.Trim()
            "CPU_SystemTotal" = $lmStatsHt.CPU_SystemTotal -as [double]
            "VSTotals_PktsPerSec" = $lmStatsHt.VSTotals_PktsPerSec -as [double]
            "MEM_used" = $lmStatsHt.MEM_used -as [double]
            "VSTotals_BitsPerSec" = $lmStatsHt.VSTotals_BitsPerSec -as [double]
            "MEM_usedPct" = $lmStatsHt.MEM_usedPct -as [double]
            "VSTotals_ConnsPerSec" = $lmStatsHt.VSTotals_ConnsPerSec -as [double]
            "VSTotals_BytesPerSec" = $lmStatsHt.VSTotals_BytesPerSec -as [double]
            "MEM_freePct" = $lmStatsHt.MEM_freePct -as [double]
            "MEM_free" = $lmStatsHt.MEM_free -as [double]
            "HA1_IsActive" = $ha1Active
            "HA2_IsActive" = $ha2Active
            "HA_Mode" = $allHt.hamode
        }) | Out-Null


        $logString += "`n`tLM: $identifier"

        # Select and Parse Virtual Services
        foreach ($vsKey in $vsHt.Keys) {
            if ($vsHt[$vsKey].MasterVSID -eq "0") {
                # regular VS
                $vs = $vsHt[$vsKey]
                $vsStats = $vsStatsHt[$vsKey]

                $identifier = "$($allHt.managementhost)-vs$($vsKey)"
                # send VS propertybag
                $pbHTArray.Add(@{
                    "objecttype" = "vs"
                    "nickname"   = $vs.NickName
                    "index"      = $identifier
                    "enabled"    = $vs.Enable
                    "status"     = $vs.Status
                    "identifier" = $identifier.Trim()
                    "ActiveConns" = $vsStats.ActiveConns -as [double]
                    "ConnsPerSec" = $vsStats.ConnsPerSec -as [double]
                }) | Out-Null

                $logString += "`n`t`tVS: $identifier`tenabled=$($vs.Enable),Status=$($vs.Status)"

				foreach ($rsKey in $rsHt.Keys) {
					if ($rsHt[$rsKey].VSIndex -eq $vs.Index ) {
						# RS (in VS)
                        $rs = $rsHt[$rsKey]
                        $rsStats = $rsStatsHt[$rsKey]
                        $identifier = "$($allHt.managementhost)-vs$($vsKey)-rs$($rsKey)" #using this as a composite key property

                        # prepare RS propertybag info
						$pbHTArray.Add(@{
							"objecttype" = "rs"
							"index" = $identifier
							"status" = $rs.Status
							"enabled" = $rs.Enable
                            "identifier" = $identifier
                            "ActiveConns" = $rsStats.ActiveConns -as [double]
                            "ConnsPerSec" = $rsStats.ConnsPerSec -as [double]
						}) | Out-Null

                        $logString += "`n`t`t`tRS: $($rsKey)-$($rs.Addr)"
                    }
                }

                # Select and Parse SubVS
                foreach ($subVSKey in $vsHt.Keys) {
                    if ($vsHt[$subVSKey].MasterVSID -eq $vs.Index) {
                        # SubVS
                        $subVS = $vsHt[$subVSKey]
                        $subVsStats = $vsStatsHt[$subVSKey]

                        $identifier = "$($allHt.managementhost)-vs$($vsKey)-subvs$($subVSKey)"
                        # send VS propertybag
                        $pbHTArray.Add(@{
                            "objecttype" = "subVS"
                            "nickname"   = $subVS.NickName
                            "index"      = $identifier
                            "enabled"    = $subVS.Enable
                            "status"     = $subVS.Status
                            "identifier" = $identifier.Trim()
                            "ActiveConns" = $subVsStats.ActiveConns -as [double]
                            "ConnsPerSec" = $subVsStats.ConnsPerSec -as [double]
                        }) | Out-Null

                        $logString += "`n`t`t`tSubVS: $identifier`tenabled=$($subVS.Enable),status=$($subVS.Status)"


                        foreach ($rsKey in $rsHt.Keys) {
                            if ($rsHt[$rsKey].VSIndex -eq $subVS.Index ) {
                                # RS (in SubVS)
                                $rs = $rsHt[$rsKey]
                                $rsStats = $rsStatsHt[$rsKey]
                                $identifier = "$($allHt.managementhost)-vs$($vsKey)-subvs$($subVSKey)-rs$($rsKey)" #using this as a composite key property

								# prepare RS propertybag info
								$pbHTArray.Add(@{
									"objecttype" = "rs"
									"index" = $identifier
									"status" = $rs.Status
									"enabled" = $rs.Enable
                                    "identifier" = $identifier
                                    "ActiveConns" = $rsStats.ActiveConns -as [double]
                                    "ConnsPerSec" = $rsStats.ConnsPerSec -as [double]
								}) | Out-Null
                                $logString += "`n`t`t`t`tRS: $($rsKey)-$($rs.Addr)"
                            }
                        }

                    }
                }
            }
        }
    } else {
        # No response from LoadMaster
        # Create LM Propertybag for a "no response" error
        $identifier = $(([System.Uri]$url).Host)

        $pbHTArray.Add(@{
            "objecttype" = "lm"
            "responds"   = "no"
            "identifier" = $identifier.Trim()
        }) | Out-Null
    }
}

Send-PropertyBag -Properties $pbHTArray -Debug $isDebugging

if ($error.Count -gt 0) {
    $scomAPI.LogScriptEvent($scriptName, $eventId, 2, $($Error.Exception))
}
else {
    $scomAPI.LogScriptEvent($scriptName, $eventId, 0, "`nProbe ran without errors." + $logString)
}

######################################
# put last in any script
foreach ($newVar in (Get-Variable -Exclude $existingVars -Scope Global).Name){
    if ($newVar -ne "existingVars") {
        $obj = Get-Variable -Name $newVar -ValueOnly
        if ("Close" -in (Get-Member -InputObject $obj).Name) {$obj.Close}
        if ("Dispose" -in (Get-Member -InputObject $obj).Name) {$obj.Dispose}
        $obj = $null
        Remove-Variable -Name "obj" -Force -Scope Global
        Remove-Variable -Name $newVar -Force -Scope Global
    }
}
Get-SCOMManagementGroupConnection | Remove-SCOMManagementGroupConnection
foreach ($newModule in ((Get-Module).Name | Where-Object{$_ -notin $existingModules})){
    Remove-Module -Name $newModule
}