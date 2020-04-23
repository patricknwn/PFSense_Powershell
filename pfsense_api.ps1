<#

.SYNOPSIS
This powershell script uses the xml-rpc feature of the pfsense to modify it.

.DESCRIPTION
This powershell script uses the xml-rpc feature of the pfsense to connect. It needs a the server addres, username and password to connect. 
Afther the connection has been made it uses the service and action variable's to modify the pfsense. 
NoTLS switch make's the script use a not secure connection
SkipCertificateCheck switch uses a secure connection, but does not check if the certificate is trusted 
At this moment the following services are suported: 
    -interface       print, 
    -Alias           print, 
    -Gateway         print,
    -staticroute     print,
    -firewall        print,
    -portfwd         print,
    -dnsResolver     print,

.PARAMETER Server
the ip/host address of the pfsense XML-RPC listener

.PARAMETER Username
the username of the account u want to use to connect to the pfsense

.PARAMETER InsecurePassword
The password of the account you want to use to connect to the pfSense. 
Be careful when using this as a script argument, since it might end up in terminal logs, SIEM's etc.

.PARAMETER Service
The service of the pfsense you want to use

.PARAMETER Action
The action you want to performe on the Service

.PARAMETER NoTLS
This switch tells the script to use an insecure connection

.PARAMETER SkipCertificateCheck
This switch tells the script to accept self-signed TLS certificates as valid TLS certificate

.EXAMPLE
Print a Service, in this case the Interface's:
./pfsense_api.ps1 -Server 192.168.0.1 admin pfsense -service Interface -action print -notls -SkipCertificateCheck

.EXAMPLE
./pfsense_api.ps1 -Server 192.168.0.1 admin pfsense -service alias -action print -notls -SkipCertificateCheck

.NOTES
Styling and best practises used from Posh: https://poshcode.gitbooks.io/powershell-practice-and-style/content/
This is a work in progress though and we're not so versed in it yet that we remember every detail.
And as usual, some personal preferences apply.

.LINK
https://github.com/RaulGrayskull/PFSense_Powershell

#>
Param
    (
    [Parameter(Mandatory=$true, HelpMessage='The pfSense network address (DNS or IP)')] [string] $Server,
    [Parameter(Mandatory=$false, HelpMessage='The Username')] [string] $Username,
    [Parameter(Mandatory=$false, HelpMessage='The Password')] [string] $InsecurePassword,
    [Parameter(Mandatory=$false, HelpMessage='The service you would like to talke to')] [string] $Service,
    [Parameter(Mandatory=$false, HelpMessage='The action you would like to do on the service')] [string] $Action,
    [Switch] $NoTLS,
    [switch] $SkipCertificateCheck
    )

# Test to see if the xmlrpc is installed, if not install
if (Get-Module -ListAvailable -Name XmlRpc) {
    Write-Host "Module exists"
} 
else {
    Install-Module -Name XmlRpc
}

# dotsource the classes
. .\classes.ps1
function ConvertTo-PFObject{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]$PFconfig,
        [Parameter(Mandatory=$false)]$PFObjectType
    )
    begin{
        $Object = (New-Object -TypeName $PFObjectType)
        $PropertyMapping = $Object::PropertyMapping
        $Collection = New-Object System.Collections.ArrayList

        $Properties = @{}
    }
    process { 
        if(($Object::section) -match "/"){
            $ObjectToParse = $PFconfig.(($Object::section).Split("/")[0]).(($Object::section).Split("/")[1])
        }
        else{
            $ObjectToParse = $PFconfig.($Object::section)
        }
        
        $PropertyValue = $null
        $index = 0

        if ($ObjectToParse[$Index]){
            while($ObjectToParse[$index]){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                    $PropertyValue = $ObjectToParse[$index].$XMLProperty.string
                    $Properties.$Property = $PropertyValue

                    $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                    $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                    $PropertyIsCollection = $PropertyDefinition.Contains("[]")

                    if($PropertyIsCollection -and $PropertyValue){
                        if($Property -eq "Detail"){$PropertyValue = $PropertyValue.Split("||")}
                        elseif($Property -eq "Address"){$PropertyValue = $PropertyValue.Split(" ")}
                        else{$PropertyValue = $PropertyValue.Split(",")}
                    
                    $PropertyTypedValue = New-Object System.Collections.ArrayList
                    ForEach($Item in $PropertyValue){
                            switch($PropertyType){
                                "PFInterface" {
                                    $PropertyTypedValue.Add(
                                        ($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item })
                                    ) | Out-Null
                                }
                            }
                        }
                    }

                }
                $Object = New-Object -TypeName $PFObjectType -Property $Properties
                $Collection.Add($Object) | Out-Null
                $index++
            }
        }
        else{
            foreach($key in $PFconfig.($Object::section).keys){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                    $PropertyValue = $null
                    $PropertyValue = $ObjectToParse.$key
                    foreach($XMLProp in $XMLProperty.Split(".")){
                        if($XMLProp -eq 'name'){
                            $PropertyValue = $key
                        }
                        else{
                            $PropertyValue = $PropertyValue.$XMLProp
                        }
                    }
                    if($PropertyValue.string){$Properties.$Property = $PropertyValue.string}
                    elseif($key.GetType() = [string]){$Properties.$Property = $PropertyValue}
                    else{$Properties.$Property = ""}
                    $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                    $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                    $PropertyIsCollection = $PropertyDefinition.Contains("[]")

                    #if($PropertyIsCollection -and $PropertyValue){
                    #    if($Property -eq "Detail"){$PropertyValue = $PropertyValue.string.Split("||")}
                    #    elseif($Property -eq "Address"){$PropertyValue = $PropertyValue.string.Split(" ")}
                    #    else{$PropertyValue = $PropertyValue.string.Split(",")}
                    # 
                    #    $PropertyTypedValue = New-Object System.Collections.ArrayList
                    #    ForEach($Item in $PropertyValue){
                    #            switch($PropertyType){
                    #                "PFInterface" {
                    #                    $PropertyTypedValue.Add(
                    #                        ($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item })
                    #                    ) | Out-Null
                    #                }
                    #            }
                    #    }
                    #}
                    
                }
            $Object = New-Object -TypeName $PFObjectType -Property $Properties
            $Collection.Add($Object) | Out-Null
            }
        }
        return $Collection

    }
}

function Format-Xml {
    <#
    .SYNOPSIS
    Pretty-print an XML object
    #>
        param(
            ## Text of an XML document. Enhance so that also XML nodes can be pretty printed, not only complete documents.
            [Parameter(ValueFromPipeline = $true)]
                [XML]$XML
        )
    
        begin {
            Write-Debug "Attach debugger here."
        }

        process {
            $StringWriter = New-Object System.IO.StringWriter;
            $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter;
            $XmlWriter.Formatting = "indented";
            $xml.WriteTo($XmlWriter);
            $XmlWriter.Flush();
            $StringWriter.Flush();
            return $StringWriter.ToString();
        }
}

function ConvertSourceDestinationAddress{
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Rules')][psobject]$SourceDestinationHasTable,
           [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        # I have kept the name conversion for the source and destination address out of the ConvertTo-PFObject because this is only used for two services
        ForEach($Item in $SourceDestinationHasTable){
            if($Item.SourceType -eq "network"){
                if($Item.SourceAddress.endswith("ip")){
                    $Item.SourceAddress= "{0} Adress" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.SourceAddress.split("ip")[0]})}
                else{$Item.SourceAddress= "{0} Net" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.SourceAddress})}
                }
            if($Item.DestType -eq "network"){
                if($Item.DestAddress.endswith("ip")){$Item.DestAddress= "{0} Adress" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.DestAddress.split("ip")[0]})}
                else{$Item.DestAddress= "{0} Net" -f $($InputObject.Config.Interfaces | Where-Object { $_.Name -eq $Item.DestAddress})}
                }
        
        }
    }
}

function Get-PFConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('Server')]
            [PFServer]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage="The section of the configuration you want, e.g. interfaces or system/dnsserver")]
            [string]$Section        
    )
    
    begin {
        # Due to some changes, this whole section thing isn't very relevant anymore and might introduce extra bugs.
        # TODO: consider removing this section thing support
        if(-not [string]::IsNullOrWhiteSpace($Section)){
            $Section = $Section -split "/" | Join-String -Separator "']['" -OutputPrefix "['" -OutputSuffix "']"
        }
    }
    
    process {
        $XMLConfig = $null

        if($InputObject.XMLConfig -and $InputObject.XMLConfig.GetType() -eq [XML] -and [string]::IsNullOrWhiteSpace($Section)){             
            $XMLConfig = $InputObject.XMLConfig
        
        } else {
            $XMLConfig = Invoke-PFXMLRPCRequest -Server $InputObject -Method 'exec_php' -MethodParameter ('global $config; $toreturn=$config{0};' -f $Section)
        }
        
        #TODO: fetch only the relevant section if contains other sections too. Low prio.
        $InputObject.XMLConfig = $XMLConfig
        $InputObject.PFconfig = (ConvertFrom-Xml -InputObject $XMLConfig)
        return $InputObject
    }    
}

function Get-PFInterface {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)   
    process { 
        $InputObject = Get-PFConfiguration $InputObject
        $PFinterfaces = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType "PFInterface"
        return $PFinterfaces 
    }
        
}
function Get-PFAlias {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject = Get-PFConfiguration $InputObject
        $Aliases = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType "PFAlias"
        return $Aliases
    }
}
function Get-PFdhcpd {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject = Get-PFConfiguration $InputObject
        $dhcpd = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType "PFdhcpd"
        return $dhcpd
    }
}

function Get-PFdhcpStaticMap {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject = Get-PFConfiguration $InputObject
        $PFdhcpStaticMap = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType "PFdhcpStaticMap"
        return $PFdhcpStaticMap
    }
}


function Get-PFFirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)

    process {
        $InputObject = Get-PFConfiguration $InputObject
        $FirewallRules = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType PFfirewallRule
#        ConvertSourceDestinationAddress -SourceDestinationHasTable $FirewallRules -InputObject $InputObject
        return $FirewallRules
    }
}

function Get-PFGateway {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject = Get-PFConfiguration $InputObject
        $GateWay = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType PFGateway
        return $GateWay
    }
}
function Get-PFNATRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject = Get-PFConfiguration $InputObject
        $NatRules = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType PFnatRule
#        ConvertSourceDestinationAddress -SourceDestinationHasTable $NatRules -InputObject $InputObject
        return $NatRules
    }

}
function Get-PFStaticRoute {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        $InputObject = Get-PFConfiguration $InputObject
        $StaticRoute = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType PFStaticRoute
        return $StaticRoute
    }
}

function Get-PFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $InputObject = Get-PFConfiguration $InputObject
        $Unbound = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType PFUnbound
        foreach($Rule in $Unbound){
            if($Rule.port -eq "0"){$Rule.port = "53"}
            if($Rule.sslport -eq "0"){$Rule.sslport = "853"}
        } 
        return $Unbound  
    }
}

function Get-PFunboundHost {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {  
        $InputObject = Get-PFConfiguration $InputObject
        $UnboundHost = ConvertTo-PFObject -PFconfig $PFconfig -PFObjectType PFunboundHost
        Return $UnboundHost
    }
}

function Invoke-PFXMLRPCRequest {
    <#
    .DESCRIPTION
        https://github.com/pfsense/pfsense/blob/master/src/usr/local/www/xmlrpc.php
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [PFServer]$Server,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [ValidateSet('host_firmware_version', 'exec_php', 'exec_shell', 
                         'backup_config_section', 'restore_config_session', 'merge_installedpackages_section', 
                         'merge_config_section', 'filter_configure', 'interfaces_carp_configure', 'reboot')]
            [string]$Method,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [psobject]$MethodParameter,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$Passthru
    )
    
    begin {
        # templates to construct the request body
        $XMLRequestTemplate =   
        "<?xml version='1.0' encoding='iso-8859-1'?>" +
        "   <methodCall>" +
        "       <methodName>pfsense.##METHOD##</methodName>" +
        "       <params>" +
        "           ##PARAMS##" +                 
        "        </params>" +
        "    </methodCall>"

        $XMLMethodParamTemplate = 
        "            <param>" +
        "                <value>" +
        "                   <##TYPE##>##VALUE##</##TYPE##>" +
        "                </value>" +
        "            </param>"
    }
    
    process {
        # TODO: implement more extensive parameter support, mostly supporting multiple parameters/xml structures
        #       currently only one parameter with type int or string (default) is supported
        if($MethodParameter){
            $XMLMethodParamType = ($MethodParameter.GetType() -eq [int]) ? 'int' : 'string'
            $XMLMethodParam = $XMLMethodParamTemplate `
                                    -replace '##TYPE##', $XMLMethodParamType `
                                    -replace '##VALUE##', $MethodParameter
                                                            
        }

        $XMLRequest = $XMLRequestTemplate `
                        -replace '##PARAMS##', $XMLMethodParam `
                        -replace'##METHOD##', $Method
        
        $URL = $Server.ToString()

        $RequestParams = @{
            ContentType                     = 'text/xml'
            uri                             = $URL
            Method                          = "post"
            Body                            = $XMLRequest
            Credential                      = $Server.Credential
            Authentication                  = "basic"
            AllowUnencryptedAuthentication  = $Server.NoTLS
            SkipCertificateCheck            = $Server.SkipCertificateCheck
            UseBasicParsing                 = $true     # just to make sure it works even when internet explorer isn't installed on the system
        }

        Write-Debug "Sending XML-RPC request to $($URL), asking the server to execute the action '$($Method)'"
        Write-Debug ($XMLRequest | Format-Xml ) -Verbose 

        try{
            $Response = Invoke-Webrequest @RequestParams
            $XMLResponse = [XML]$Response
            $FaultCode = ($XMLResponse | Select-Xml -XPath '//member[name="faultCode"]/value/int').Node.InnerText
            $FaultReason = ($XMLResponse | Select-Xml -XPath '//member[name="faultString"]/value/string').Node.InnerText

        # most likely reason for this error is that the returened message was invalid XML, probably because you messed up ;)
        } catch [System.Management.Automation.RuntimeException] {
            if(-not $Response){
                throw [System.TimeoutException]::new("Unable to contact the pfSense XML-RPC server at $URL")

            } else {
                Write-Debug "The returned content-type was: $($Response.Headers.'Content-Type')"
                Write-Debug "The message from the server could not be converted to XML. This is what the server returned: $($Response.Content)" 
                Write-Debug "Your message to the server was: $($XMLRequest)"
            }

        # unknow exception, let the user know
        } catch {
            Write-Error $_.Exception.Message
            Write-Error $_.ScriptStackTrace
        }

        if([string]::IsNullOrWhiteSpace($FaultCode) -and [string]::IsNullOrWhiteSpace($FaultReason)){
            return ($Passthru) ? $Response : $XMLResponse

        } else {
            switch($FaultReason){
                'Authentication failed: Invalid username or password' {
                    throw [System.Security.Authentication.InvalidCredentialException]::New("Invalid credentials to access XML-RPC at $URL")
                }
                'Authentication failed: not enough privileges' {
                    throw [System.Security.AccessControl.PrivilegeNotHeldException]::New("Insuffucient privileges to access XML-RPC at $URL")
                }
                'Unable to parse request XML' {
                    throw [System.Xml.XmlException]::New('The server was unable to parse the XML-RPC request message.')
                }
                default {
                    Write-Debug "Sent request: $($XMLRequestTemplate)"
                    Write-Debug "Server response: $($Response.Content)"                
                    throw "Server returned fault code $FaultCode with reason '$FaultReason'"
                }
            }                
        }
    }
}

function Test-PFCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [psobject]$Server
    )
    
    process {
        try {
            if(-not $Server.Credential -or $Server.Credential.GetType() -ne [pscredential]){
                throw [System.Security.Authentication.InvalidCredentialException]::New('Server object has no stored credential')
            }
            
            Write-Debug "Trying credentials for user '$($Server.Credential.UserName)'"
            Invoke-PFXMLRPCRequest -Server $Server -Method 'host_firmware_version' | Out-Null

        # catch when use of the system is not possible with this credentials
        } catch [System.Security.Authentication.InvalidCredentialException],
                [System.Security.AccessControl.PrivilegeNotHeldException] {
            Write-Debug $_.Exception.Message
            Write-Output "ERROR: $($_.Exception.Message)" -ForegroundColor red
            return $false

        # catch connection timeout, quit the program when this is detected
        } catch [System.TimeoutException] {
            throw $_.Exception

        # maybe something happened, but we are able to use the system
        } catch {
            Write-Debug $_.Exception.Message
            Write-Debug $_.ScriptStackTrace
        }

        return $true
    }    
}

## BEGIN OF CONTROLLER LOGIC, should be moved to a different script later in order to be able to dotsource this file in your own scripts.
# since debugging dotsourced files s*, leave it here for now until we're ready for a first release
# TODO: create a switch for the program to skip this contoller logic and be able to test dotsourcing this file in your own scripts too.
Clear-Host

$PFServer = [PFServer]@{
    Credential = $null 
    Address = $Server
    NoTLS = $NoTLS
    SkipCertificateCheck = $SkipCertificateCheck
}

# Warn the user if no TLS encryption is used
if($PFServer.NoTLS){
    Write-Warning "Your administrative level credentials are being transmitted over an INSECURE connection!"
}

# Test credentials before we continue.
Write-Progress -Activity "Testing connection and your credentials" -Status "Connecting..." -PercentComplete -1
try{
    if(-not [string]::IsNullOrWhiteSpace($Username)){
        if(-not [string]::IsNullOrWhiteSpace($InsecurePassword)){
            $Password = ConvertTo-SecureString -String $InsecurePassword -AsPlainText -Force
            $PFServer.Credential = New-Object System.Management.Automation.PSCredential($Username, $Password) 

        } else {
            $PFServer.Credential = Get-Credential -UserName $Username
        }
    }
    while(-not (Test-PFCredential -Server $PFServer)){ $PFServer.Credential = Get-Credential }

} catch [System.TimeoutException] {
    Write-Error -Message $_.Exception.Message
    exit 4

} finally {
    Write-Progress -Activity "Testing connection and your credentials" -Completed
}

# Get all config information so that we can see what's inside
$PFServer = Get-PFConfiguration -Server $PFServer -Section  "" 
if(-not $PFServer.XMLConfig -or $PFServer.XMLConfig.GetType() -ne [XML]){ 
    Write-Error "Unable to fetch the pfSense configuration."
    exit 1
}

# We will have frequent reference to the [PFInterface] objects, to make them readily available
$PFServer.Config.Interfaces = $PFServer | Get-PFInterface

# add the IPv6 LinkLocal name and description so these can be translated
foreach($interface in $PFServer.Config.Interfaces){
    $Properties = @{}
    if($interface.DESCRIPTION){
        # If the interface has a description set it as part of it's ipv6 linklocal name
        $Properties.Name = "_lloc{0}" -f $interface.name
        $Properties.Description = "{0}IpV6LinkLocal" -f $interface.DESCRIPTION
    }
    else{
        # else use the name as part of the ipv6 linklocal name
        $Properties.Name = "_lloc{0}" -f $interface.name
        $Properties.Description = "{0}IpV6LinkLocal" -f $interface.name
    }
    $Object = New-Object -TypeName PFInterface -Property $Properties
    $PFServer.Config.Interfaces = $PFServer.Config.Interfaces + $Object     
}
# add some default name translations to the interface's like "all" and "Loopback"
$StaticInterface = @{
    all = 'all'
    lo0 = 'Loopback'
}
$StaticInterface.keys | %{
    $Properties = @{}
    $Properties.name = $_
    $Properties.Description = $StaticInterface.Item($_)
    $Object = New-Object -TypeName PFInterface -Property $Properties
    $PFServer.Config.Interfaces = $PFServer.Config.Interfaces + $Object 
}

# define the possible execution flows
$Flow = @{
    "alias" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFAlias | Format-Table *"#the star makes the format table show more than 10 column's
    }

    "gateway" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFGateway | Format-Table *"
    }

    "interface" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFInterface | Format-Table *"
    }

    "StaticRoute" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFStaticRoute | Format-table *"
    }

    "dnsResolver" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFunbound | Format-table *"
    }    

    "dnsResolverHost" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFunboundHost | Format-table *"
    }   

    "portfwd" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFnatRule | Format-table *"
    }    
    "Firewall" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFfirewallRule | Format-table *" 
    } 
    "dhcpd" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFdhcpd | Format-table *" 
    } 
    "dhcpStaticMap" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFdhcpStaticMap | Format-table * -autosize" 
    } 

}

# execute requested flow
try{
    if(-not $Flow.ContainsKey($Service)){  Write-Host "Unknown service '$Service'" -ForegroundColor red; exit 2 }
    if(-not $Flow.$Service.ContainsKey($Action)){ Write-Host "Unknown action '$Action' for service '$Service'" -ForegroundColor red; exit 3 }

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer


} catch {
    Write-Error $_.Exception
    exit 1    
}