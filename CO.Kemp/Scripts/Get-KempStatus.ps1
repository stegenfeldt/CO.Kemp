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
                $all.Add($allXml.Name, $allXml.InnerText)
            }
        }
        if ($all.Count -gt 1) {
            #got results, add proper management property
            $all.Add("managementhost", $(([System.Uri]$this.AdminAdress).Host))
        }
        return $all
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
                $all.Add($allXml.Name, $allXml.InnerText)
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
                $all.Add($allXml.Name, $allXml.InnerText)
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
            )
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
            )
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
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #DevSkim: ignore DS126185 until 2019-06-01 
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
        # Cluster API is not accessible unless you're admin, we'll deal with that later
        #$clHt | ConvertTo-Json | Out-File -FilePath "$($env:TEMP)\cl.json"
    }

    if ($allHt.Count -gt 0) {
        # got data in allHT, which means here's a LoadMaster returned.

        [string] $identifier = $allHt.managementhost
        # Create LM Propertybag
        $pbHTArray.Add(@{
            "objecttype" = "lm"
            "hostname"   = $allHt.managementhost
            "responds"   = "yes"
            "identifier" = $identifier.Trim()
        }) | Out-Null

        $logString += "`n`tLM: $identifier"

        # Select and Parse Virtual Services
        foreach ($vsKey in $vsHt.Keys) {
            if ($vsHt[$vsKey].MasterVSID -eq "0") {
                # regular VS
                $vs = $vsHt[$vsKey]

                $identifier = "$($allHt.managementhost)-vs$($vsKey)"
                # send VS propertybag
                $pbHTArray.Add(@{
                    "objecttype" = "vs"
                    "nickname"   = $vs.NickName
                    "index"      = $identifier
                    "enabled"    = $vs.Enable
                    "status"     = $vs.Status
                    "identifier" = $identifier.Trim()
                }) | Out-Null

                $logString += "`n`t`tVS: $identifier`tenabled=$($vs.Enable),Status=$($vs.Status)"

				foreach ($rsKey in $rsHt.Keys) {
					if ($rsHt[$rsKey].VSIndex -eq $vs.Index ) {
						# RS (in VS)
                        $rs = $rsHt[$rsKey]
                        $identifier = "$($allHt.managementhost)-vs$($vsKey)-rs$($rsKey)" #using this as a composite key property

                        # prepare RS propertybag info
						$pbHTArray.Add(@{
							"objecttype" = "rs"
							"index" = $identifier
							"status" = $rs.Status
							"enabled" = $rs.Enable
							"identifier" = $identifier
						})

                        $logString += "`n`t`t`tRS: $($rsKey)-$($rs.Addr)"
                    }
                }

                # Select and Parse SubVS
                foreach ($subVSKey in $vsHt.Keys) {
                    if ($vsHt[$subVSKey].MasterVSID -eq $vs.Index) {
                        # SubVS
                        $subVS = $vsHt[$subVSKey]

                        $identifier = "$($allHt.managementhost)-vs$($vsKey)-subvs$($subVSKey)"
                        # send VS propertybag
                        $pbHTArray.Add(@{
                            "objecttype" = "subVS"
                            "nickname"   = $subVS.NickName
                            "index"      = $identifier
                            "enabled"    = $subVS.Enable
                            "status"     = $subVS.Status
                            "identifier" = $identifier.Trim()
                        }) | Out-Null

                        $logString += "`n`t`t`tSubVS: $identifier`tenabled=$($subVS.Enable),status=$($subVS.Status)"


                        foreach ($rsKey in $rsHt.Keys) {
                            if ($rsHt[$rsKey].VSIndex -eq $subVS.Index ) {
                                # RS (in SubVS)
                                $rs = $rsHt[$rsKey]
                                $identifier = "$($allHt.managementhost)-vs$($vsKey)-subvs$($subVSKey)-rs$($rsKey)" #using this as a composite key property

								# prepare RS propertybag info
								$pbHTArray.Add(@{
									"objecttype" = "rs"
									"index" = $identifier
									"status" = $rs.Status
									"enabled" = $rs.Enable
									"identifier" = $identifier
								})
                                $logString += "`n`t`t`t`tRS: $($rsKey)-$($rs.Addr)"
                            }
                        }

                    }
                }
            }
        }
    }
}

Send-PropertyBag -Properties $pbHTArray -Debug $isDebugging

if ($error.Count -gt 0) {
    $scomAPI.LogScriptEvent($scriptName, $eventId, 2, $($Error.Exception))
}
else {
    $scomAPI.LogScriptEvent($scriptName, $eventId, 0, "`nProbe ran without errors." + $logString)
}