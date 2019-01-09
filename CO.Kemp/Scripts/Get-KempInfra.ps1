param(
    [string] $LoadMasterBaseUrls
	, [string] $Debug
)

$Error.Clear() # Fresh start!
$scriptName = "Get-KempInfra.ps1"
$eventId = 18002
$isDebugging = $false

$knownDebugHosts = @(
    "Visual Studio Code Host"
    "Windows PowerShell ISE Host"
)
if ($host.Name -in $knownDebugHosts) {
    # script is running in a known debug environment, set debug values
    $tempDir = "$env:TEMP\CO.Kemp"
    $LoadMasterBaseUrls = "https://avmk01.westeurope.cloudapp.azure.com:8443/" #my free tier azure appliance, perfect for development, may be offline
    $sourceId = '{6b4f36a3-461e-4340-90c9-5634411d216a}' #dummy value for debugging
    $targetId = '{46c128a4-39c6-4b51-980f-3622293689f3}' #dummy value for debugging
    if (!(Test-Path -Path $tempDir)) {New-Item -Path $tempDir -ItemType Directory}
    $isDebugging = $true
}
else {
    $sourceId = '$MPElement$'
    $targetId = '$Target/Id$'
}


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

$kempUser = "$RunAs[Name='CO.Kemp.KempRunasProfile']/UserName$"
$kempPass = "$RunAs[Name='CO.Kemp.KempRunasProfile']/Password$"

$urls = $LoadMasterBaseUrls.Split(",")

# Create SCOM API Object
$scomAPI = New-Object -comObject 'MOM.ScriptAPI'
$scomAPI.LogScriptEvent($scriptName, $eventId, 0, "`nDiscovery started by $(whoami) using $($kempUser) in `"$($host.Name)`".`nLoadMasterBaseUrls = $($LoadMasterBaseUrls)`nsourceId = $($sourceId)`ntargetId = $($targetId)")
$discoveryData = $scomApi.CreateDiscoveryData(0, $sourceId, $targetId)

$logString = "`n"

foreach ($url in $urls) {
    $username = $kempUser
    $password = ConvertTo-SecureString -String $kempPass -AsPlainText -Force

    $kemp = [Kemp]::new($url, $username, $password)

    $kemp.ValidateUrl($kemp.AdminAdress)

    $logString += "Connecting to $url"

    $vsHt = $kemp.GetVirtualServices() #VirtualService (incl. SubVS) information
    $rsHt = $kemp.GetRealServers() # RealServer information
    $allHt = $kemp.GetAll() # This is where you get LoadMaster node information
    
    # Cluster API is not accessible unless you're admin
    #$clHt = $kemp.GetClusters()
    #$fqdnHt = $kemp.ListFQDNs()
    #$ipHt = $kemp.ListIPs()


    # Saving to disk, only for manual analysis during development
    if ($isDebugging -or $Debug -eq 'true') {
        $vsHt | ConvertTo-Json | Out-File -FilePath "$tempDir\vs.json"
        $rsHt | ConvertTo-Json | Out-File -FilePath "$tempDir\rs.json"
        $allHt | ConvertTo-Json | Out-File -FilePath "$tempDir\all.json"
        
        # Cluster API is not accessible unless you're admin
        #$clHt | ConvertTo-Json | Out-File -FilePath "$($env:TEMP)\cl.json"
        #$fqdnHt | ConvertTo-Json | Out-File -FilePath "$tempDir\fqdn.json"
    }

    if ($allHt.Count -gt 0) {
        # got data in allHT, which means here's a LoadMaster returned.
        # prepare $allHt
        if ($allHt.hamode -eq "0") {
            $allHt["ha1hostname"] = ""
            $allHt["ha2hostname"] = ""
        }

        # Instantiate LoadMaster instance
        $lmInstance = $discoveryData.CreateClassInstance("$MPElement[Name='CO.Kemp.LoadMaster']$")
        $lmInstance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", $allHt.managementhost)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/managementurl$", $url)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/hostname$", $allHt.managementhost)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/version$", $allHt.version)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/ha1hostname$", $allHt.ha1hostname)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/ha2hostname$", $allHt.ha2hostname)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/wuiport$", $allHt.wuiport)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/sshport$", $allHt.sshport)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/snmplocation$", $allHt.snmplocation)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/serialnumber$", $allHt.serialnumber.Trim())
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/ntphost$", $allHt.ntphost)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/dfltgw$", $allHt.dfltgw)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/timezone$", $allHt.timezone)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/SyslogPort$", $allHt.SyslogPort)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/radiusserver$", $allHt.radiusserver)
        $lmInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/nameserver$", $allHt.nameserver)
        $discoveryData.AddInstance($lmInstance)

        $logString += "`n`tLM: $($allHt.managementhost)"

        # Instantiate KempDA->LoadMaster relationship
        $lmDAInstance = $discoveryData.CreateClassInstance("$MPElement[Name='CO.Kemp.LoadMasterDA']$") #DA is singleton, don't need to add key properties
        $lmDALMContainmentRelationship = $discoveryData.CreateRelationshipInstance("$MPElement[Name='CO.Kemp.LoadMasterDAContainsLoadMaster']$")
        $lmDALMContainmentRelationship.source = $lmDAInstance
        $lmDALMContainmentRelationship.target = $lmInstance
        $discoveryData.AddInstance($lmDALMContainmentRelationship)

		
        # Select and Parse Virtual Services
        foreach ($vsKey in $vsHt.Keys) {
            if ($vsHt[$vsKey].MasterVSID -eq "0") {
                # regular VS
                $vs = $vsHt[$vsKey]
                $identifier = "$($allHt.managementhost)-vs$($vsKey)" #using this as a composite key property
                # Instantiate VirtualService
                $vsInstance = $discoveryData.CreateClassInstance("$MPElement[Name='CO.Kemp.VirtualService']$")
				$vsInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/hostname$", $allHt.managementhost) #for LM->VS Relationship
				$vsInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/managementurl$", $url) #for LM->VS Relationship
                $vsInstance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", $vs.NickName)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/VSIndex$", $identifier)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/MasterVSID$", $vs.MasterVSID)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/Port$", $vs.Port)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/NickName$", $vs.NickName)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/Protocol$", $vs.Protocol)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/QoS$", $vs.QoS)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/Layer$", $vs.Layer)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/VStype$", $vs.VStype)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/NumberOfRSs$", $vs.NumberOfRSs)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/CheckType$", $vs.CheckType)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/CheckUrl$", $vs.CheckUrl)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/ForceL7$", $vs.ForceL7)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/ForceL4$", $vs.ForceL4)
                $vsInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/AlertThreshold$", $vs.AlertThreshold)
                $discoveryData.AddInstance($vsInstance)

                $logString += "`n`t`tVS: $($vsKey)-$($vs.NickName)"

                <#
				# Instantiate LoadMaster->VirtualService relationship
                $lmVSHostingRelationship = $discoveryData.CreateRelationshipInstance("$MPElement[Name='CO.Kemp.LoadMasterHostsVirtualService']$")
                $lmVSHostingRelationship.source = $lmInstance
                $lmVSHostingRelationship.target = $vsInstance
                $discoveryData.AddInstance($lmVSHostingRelationship)
				#>
				
                foreach ($rsKey in $rsHt.Keys) {
                    if ($rsHt[$rsKey].VSIndex -eq $vs.Index ) {
                        # RS (in VS)
                        $rs = $rsHt[$rsKey]
                        $identifier = "$($allHt.managementhost)-vs$($vsKey)-rs$($rsKey)" #using this as a composite key property

                        # Instantiate RS
                        $rsInstance = $discoveryData.CreateClassInstance("$MPElement[Name='CO.Kemp.RealServer']$")
                        $rsInstance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", "$($rs.Addr):$($rs.Port) ($($vs.NickName))")
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/RsIndex$", $identifier)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Forward$", $rs.Forward)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Addr$", $rs.Addr)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Weight$", $rs.Weight)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Critical$", $rs.Critical)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Follow$", $rs.Follow)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Port$", $rs.Port)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Limit$", $rs.Limit)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/VSIndex$", $rs.VSIndex)
                        $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/DnsName$", $rs.DnsName)
                        $discoveryData.AddInstance($rsInstance)

                        $logString += "`n`t`t`tRS: $($rsKey)-$($rs.Addr)"

                        # Instantiate VirtualService->SubVirtualService relationsship
                        $vsRSContainmentRelationship = $discoveryData.CreateRelationshipInstance("$MPElement[Name='CO.Kemp.VirtualServiceContainsRealServer']$")
                        $vsRSContainmentRelationship.source = $vsInstance
                        $vsRSContainmentRelationship.target = $rsInstance
                        $discoveryData.AddInstance($vsRSContainmentRelationship)
                    }
                }

                # Select and Parse SubVS
                foreach ($subVSKey in $vsHt.Keys) {
                    if ($vsHt[$subVSKey].MasterVSID -eq $vs.Index) {
                        # SubVS
                        $subVS = $vsHt[$subVSKey]
						$hostIdentifier = "$($allHt.managementhost)-vs$($vsKey)"
                        $identifier = "$($allHt.managementhost)-vs$($vsKey)-subvs$($subVSKey)" #using this as a composite key property

                        # Instantiate SubVS
                        $subVSInstance = $discoveryData.CreateClassInstance("$MPElement[Name='CO.Kemp.SubVirtualService']$")
                        $subVSInstance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", $subVS.NickName)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/VSIndex$", $identifier)
						$subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.VirtualService']/VSIndex$", $hostIdentifier) # for VS->SubVS hosting relationship
						$subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/hostname$", $allHt.managementhost) #for LM->VS Relationship
						$subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.LoadMaster']/managementurl$", $url) #for LM->VS Relationship
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/MasterVSID$", $subVS.MasterVSID)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/Port$", $subVS.Port)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/NickName$", $subVS.NickName)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/Protocol$", $subVS.Protocol)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/QoS$", $subVS.QoS)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/Layer$", $subVS.Layer)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/VStype$", $subVS.VStype)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/NumberOfRSs$", $subVS.NumberOfRSs)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/CheckType$", $subVS.CheckType)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/CheckUrl$", $subVS.CheckUrl)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/ForceL7$", $subVS.ForceL7)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/ForceL4$", $subVS.ForceL4)
                        $subVSInstance.AddProperty("$MPElement[Name='CO.Kemp.SubVirtualService']/AlertThreshold$", $subVS.AlertThreshold)
                        $discoveryData.AddInstance($subVSInstance)

                        $logString += "`n`t`t`tSubVS: $($subVSKey)-$($subVS.NickName)"

						<#
                        # Instantiate VirtualService->SubVirtualService relationsship
                        $vsSubVSHostingRelationship = $discoveryData.CreateRelationshipInstance("$MPElement[Name='CO.Kemp.VirtualServiceHostsSubVirtualService']$")
                        $vsSubVSHostingRelationship.source = $vsInstance
                        $vsSubVSHostingRelationship.target = $subVSInstance
                        $discoveryData.AddInstance($vsSubVSHostingRelationship)
						#>

                        foreach ($rsKey in $rsHt.Keys) {
                            if ($rsHt[$rsKey].VSIndex -eq $subVS.Index ) {
                                # RS (in SubVS)
                                $rs = $rsHt[$rsKey]
                                $identifier = "$($allHt.managementhost)-vs$($vsKey)-subvs$($subVSKey)-rs$($rsKey)" #using this as a composite key property

                                # Instantiate RS
                                $rsInstance = $discoveryData.CreateClassInstance("$MPElement[Name='CO.Kemp.RealServer']$")
                                $rsInstance.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", "$($rs.Addr):$($rs.Port) ($($subVS.NickName))")
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/RsIndex$", $identifier)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Forward$", $rs.Forward)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Addr$", $rs.Addr)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Weight$", $rs.Weight)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Critical$", $rs.Critical)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Follow$", $rs.Follow)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Port$", $rs.Port)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/Limit$", $rs.Limit)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/VSIndex$", $rs.VSIndex)
                                $rsInstance.AddProperty("$MPElement[Name='CO.Kemp.RealServer']/DnsName$", $rs.DnsName)
                                $discoveryData.AddInstance($rsInstance)

                                $logString += "`n`t`t`t`tRS: $($rsKey)-$($rs.Addr)"

                                # Instantiate VirtualService->SubVirtualService relationsship
                                $subVSRSContainmentRelationship = $discoveryData.CreateRelationshipInstance("$MPElement[Name='CO.Kemp.SubVirtualServiceContainsRealServer']$")
                                $subVSRSContainmentRelationship.source = $subVSInstance
                                $subVSRSContainmentRelationship.target = $rsInstance
                                $discoveryData.AddInstance($subVSRSContainmentRelationship)
                            }
                        }
                    }
                }
            }
        }
    }
}

# Return discovery data to workflow...
if ($isDebugging) {
    # or console/file, if we're debugging
    $scomAPI.AddItem($discoveryData)
    $scomAPI.ReturnItems()
}
else {
    $discoveryData
}

if ($error.Count -gt 0) {
    $scomAPI.LogScriptEvent($scriptName, $eventId, 2, $($error | ConvertTo-Json))
}
else {
    $scomAPI.LogScriptEvent($scriptName, $eventId, 0, "`nDiscovery ran without errors." + $logString)
}