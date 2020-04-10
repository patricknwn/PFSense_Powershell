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
the ip address of the pfsense

.PARAMETER Notls
This switch tells the script to use a non ssl connection

.PARAMETER Username
the username of the account u want to use to connect to the pfsense

.PARAMETER Service
The service of the pfsense you want to use

.PARAMETER Action
The action you want to performe on the Service

.EXAMPLE
Print a Service, in this case the Interface's:
./PFsense_api_xml_rpc.ps1 -Server 192.168.0.1 admin pfsense -service Interface -action print -notls -SkipCertificateCheck

.EXAMPLE
./PFsense_api_xml_rpc.ps1 -Server 192.168.0.1 admin pfsense -service alias -action print -notls -SkipCertificateCheck

.NOTES
Put some notes here.

.LINK
https://github.com/RaulGrayskull/PFSense_Powershell

#>

Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='The Server address')] [String] $Server,
    [Parameter(Mandatory=$false, Position=1,HelpMessage='The Username')] [string] $Username,
    [Parameter(Mandatory=$false, Position=2,HelpMessage='The Password')] [string] $InsecurePassword,
    [Parameter(Mandatory=$false, Position=3,HelpMessage='The service you would like to talke to')] [string] $Service,
    [Parameter(Mandatory=$false, Position=4,HelpMessage='The action you would like to do on the service')] [string] $Action,
    [Switch] $NoTLS,
    [switch] $SkipCertificateCheck
    )



# classes to build:
<#
dhcpd
dhcpdv6
syslog
nat
filter = firewall
aliases
load_balancer
openvpn
unbound = dnsresolver <= strange things happen here
cert = cerificates
#>

class PFInterface {
    [string]$Name
    [string]$Interface
    [string]$Description
    [string]$IPv4Address    # should be [ipaddress] object, but that's for later, is a native powershell object
    [string]$IPv4Subnet
    [string]$IPv4Gateway    # should be [PFGateway] object, but that's for later
    [string]$IPv6Address    # should be [ipaddress] object, but that's for later
    [string]$IPv6Subnet
    [string]$IPv6Gateway    # should be [PFGateway] object, but that's for later
    [string]$Trackv6Interface
    [string]$Trackv6PrefixId
    [bool]$BlockBogons
    [string]$Media
    [string]$MediaOpt
    [string]$DHCPv6DUID
    [string]$DHCPv6IAPDLEN

    static [string]$Section = "interfaces"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Interface = "if"
        Description = "descr"
        IPv4Address = "ipaddr"
        IPv4Subnet = "subnet"
        IPv4Gateway = "gateway"
        IPv6Address = "ipaddrv6"
        IPv6Subnet = "subnetv6"
        IPv6Gateway = "gatewayv6"
        Trackv6Interface = "track6-interface"
        Trackv6PrefixId = "track6-prefix-id"
        DHCPv6DUID = "dhcp6-duid"
        DHCPv6IAPDLEN = "dhcp6-ia-pd-len"
    }

    [string] ToString(){
        return ([string]::IsNullOrWhiteSpace($this.Description)) ? $this.Name : $this.Description
    }
}

class PFServer {
    [string]$Address
    [pscredential]$Credential
    [int]$Port
    [bool]$NoTLS
    [bool]$SkipCertificateCheck = $false
}

class PFStaticRoute {
    [string]$Network
    [string]$Gateway    # should be [PFGateway] object, but that's for later
    [string]$Description
    
    static [string]$Section = "staticroutes/route"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        Description = "descr"
    }
}

class PFGateway {
    [psobject]$Interface
    [string]$Gateway
    [string]$Monitor
    [string]$Name
    [string]$Weight
    [string]$IPProtocol
    [string]$Description

    static [string]$Section = "gateways/gateway_item"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Description = "descr"
    }
}

class PFAlias {
    [string]$Name
    [string]$Type
    [string[]]$Address
    [string]$Description
    [string[]]$Detail

    static [string]$Section = "aliases/alias"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Description = "descr"
    }
}

class PFunbound {
    [string[]]$active_interface
    [string[]]$outgoing_interface
    [bool]$dnssec
    [bool]$enable
    [int]$port
    [int]$sslport
    [string[]]$hosts
    [string[]]$domainoverrides

    static [string]$Section = "unbound"
    static $PropertyMapping = @{ 
        active_interface = "active_interface"
        outgoing_interface = "outgoing_interface"
    }
}

class PFnatRule {
    [string]$SourceType
    [string]$SourceAddress
    [string]$SourcePort
    [string]$DestType
    [string]$DestAddress
    [string]$DestPort
    [string]$protocol
    [string]$target
    [string]$LocalPort
    [string]$interface
    [string]$Description
    
    static [string]$Section = "nat/rule"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        LocalPort = "local-port"
        Description = "descr"
        SourceType = "source"
        SourceAddress= "source"
        SourcePort = "source"
        DestType = "destination"
        DestAddress= "destination"
        DestPort = "destination"
        
    }
}

class PFFirewallRule {
    [string]$floating
    [string]$quick
    [string]$disabled
    [string]$log
    [string]$type
    [string]$ipprotocol
    [string[]]$interface
#    [string]$tracker , This is not the way the pfsense select's the order so no need to print this
    [string]$SourceType
    [string]$SourceAddress
    [string]$SourcePort
    [string]$DestType
    [string]$DestAddress
    [string]$DestPort
    [string]$Description

    
    static [string]$Section = "filter/rule"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        Description = "descr"
        SourceType = "source"
        SourceAddress= "source"
        SourcePort = "source"
        DestType = "source"
        DestAddress= "destination"
        DestPort = "destination"
    }
}

class PFFirewallseparator {
    [string]$row
    [string]$text
    [string]$color
    [string]$interface

    static [string]$Section = "filter/separator"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        interface = "if"
    }
}

function ConvertTo-PFObject {
    [CmdletBinding()]
    param (
        ## The XML-RPC response message
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
            [XML]$XML,
        # The object type (e.g. PFInterface, PFStaticRoute, ..) to convert to
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [ValidateSet('PFInterface','PFStaticRoute','PFGateway','PFalias','PFunbound','PFnatRule','PFfirewallRule','PFFirewallseparator')]
            [string]$PFObjectType
    )
    
    begin {
        $Collection = New-Object System.Collections.ArrayList
        $Object = (New-Object -TypeName "$PFObjectType")
        $Section = $Object::Section
        $PropertyMapping = $Object::PropertyMapping

        if(-not $PropertyMapping){
            throw [System.Data.NoNullAllowedException]::new("Object of type $($PFObjectType) is missing the static 'PropertyMapping' property")
        }

        if(-not $Section){
            throw [System.Data.NoNullAllowedException]::new("Object of type $($PFObjectType) is missing the static 'Section' property")
        }
    }
    
    process {
        # select the root of the object. This is the node that contains all the individual objects.
        # we have three choices basically: 
        # 1) we have the whole system configuration
        #       XPath to section: /methodResponse/params/param/value/struct/member[name=$section]/value
        # 2) we have the parent section of this object
        #       XPath to section: /methodResponse/params/param/value/struct/member[name=$section]/value
        # 3) we have only the very specific (sub)section
        #       XPath to section: /methodResponse/params/param/value
        $XMLSection = Select-Xml -Xml $XML -XPath '/methodResponse/params/param/value'
        ForEach($Subsection in $($Section -split '/')){
            $XMLSubsection = Select-Xml -XML $XMLSection.Node -XPath "./struct/member[name='$Subsection']/value"
            if($XMLSubsection){ $XMLSection = $XMLSubsection }
        }

        # Two XPath to get each individual item:
        #   XPath: ./struct/member (for associative array in the original PHP code)
        #   XPath: ./array/data/value (for index-based array in the original PHP code)
        $XMLObjects = Select-Xml -XML $XMLSection.Node -XPath "./struct/member | ./array/data/value"
        ForEach($XMLObject in $XMLObjects){    
            $XMLObject = [xml]$XMLObject.Node.OuterXML # weird that it's necessary, but as its own XML object it works           
            $Properties = @{}

            $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                $Property = $_.Name
                $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                $PropertyValue = $null

                # Property Name is a bit special, it can be
                # 1) the key in the associative array
                #       XPath: ./member/name
                # 2) a normal property value in the property array
                #       XPath: //member[name='name']/value/string
                if($Property -eq "Name"){
                    $PropertyValueXPath = "./member/name"
                    $PropertyValue = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPath).Node.InnerText
                }

                if(-not $PropertyValue){
                    $PropertyValueXPath = "//member[name='$($XMLProperty)']/value/string"
                    $PropertyValue = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPath).Node.InnerText
                }

                if(($Property -eq "SourceType") -or ($Property -eq "DestType")){
                    $PropertyValueXPathname = "//member[name='$($XMLProperty)']/value/struct/member"
                    $Propertytemp = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPathname)
                    $PropertyValue = "{0}" -f $(if(($Propertytemp.Node.Name -eq "Network") -or ($Propertytemp.Node.Name -eq "address")){$Propertytemp.Node.Name})
                }
                elseif(($Property -eq "SourceAddress") -or ($Property -eq "DestAddress")){
                    $PropertyValueXPathname = "//member[name='$($XMLProperty)']/value/struct/member"
                    $Propertytemp = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPathname)
                    $PropertyValue = "{0}" -f $(if(($Propertytemp.Node.Name -eq "Network") -or ($Propertytemp.Node.Name -eq "address")){$Propertytemp.Node.value.string})
                }
                elseif(($Property -eq "SourcePort") -or ($Property -eq "DestPort")){
                    $PropertyValueXPathname = "//member[name='$($XMLProperty)']/value/struct/member"
                    $Propertytemp = (Select-Xml -XML $XMLObject -XPath $PropertyValueXPathname)
                    $PropertyValue = if($Propertytemp[1]){$Propertytemp[1].Node.value.string}
                
                    
                }
                
                $Properties.$Property = $PropertyValue
            }

            $Object = New-Object -TypeName $PFObjectType -Property $Properties
            [void]$Collection.Add($Object)
        }

        return $Collection
    }
    
    end {}
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

function Get-PFConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('Server')]
            [psobject]$InputObject,
        [Parameter(Mandatory=$false, HelpMessage="The section of the configuration you want, e.g. interfaces or system/dnsserver")]
            [string]$Section        
    )
    
    begin {
        if(-not [string]::IsNullOrWhiteSpace($Section)){
            $Section = $Section -split "/" | Join-String -Separator "']['" -OutputPrefix "['" -OutputSuffix "']"
        }
    }
    
    process {
        $XMLConfig = $null

        if($InputObject.GetType() -eq [XML]){             
            $XMLConfig = $InputObject 
            #TODO: fetch only the relevant section if contains other sections too. Low prio.

        } elseif($InputObject.GetType() -eq [PFServer]){
            $XMLConfig = Invoke-PFXMLRPCRequest -Server $InputObject -Method 'exec_php' -MethodParameter ('global $config; $toreturn=$config{0};' -f $Section)
        }

        return $XMLConfig
    }    
}

function Get-PFInterface {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)   
    process { return $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFInterface }
}

function Get-PFStaticRoute {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process { return $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFStaticRoute }
}

function Get-PFGateway {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $Gateways = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFGateway
        $Interfaces = $InputObject | Get-PFInterface

        # replace the text of the gateway with its actual object
        ForEach($Gateway in $Gateways){
            $Gateway.Interface = $Interfaces | Where-Object { $_.Name -eq $Gateway.Interface }
        }

        return $Gateways
    }
}

function Get-PFAlias {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $Aliases = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFalias 
        ForEach($Alias in $Aliases){
            $Alias.Address = $Alias.Address -split " "
            $Alias.detail = $Alias.detail.split("||") # used .split here because otherwise it would split on each charater
        }
        
        return $Aliases
    }
}

function Get-PFunbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $Unbound = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFunbound

        return $Unbound
    }
}

function Get-PFnatRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $NatRules = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFnatRule
        $Interfaces = $InputObject | Get-PFInterface

        # replace the text of the gateway with its actual object
        ForEach($NatRule in $NatRules){
            $NatRule.Interface = $Interfaces | Where-Object { $_.Name -eq $NatRule.Interface }
            if($NatRule.SourceType -eq "network"){
                if($NatRule.SourceAddress.endswith("ip")){$NatRule.SourceAddress= "{0} Address" -f $($Interfaces | Where-Object { $_.Name -eq $NatRule.SourceAddress.split("ip")[0]})}
                else{$NatRule.SourceAddress= "{0} Net" -f $($Interfaces | Where-Object { $_.Name -eq $NatRule.SourceAddress})}
            }
            if($NatRule.DestType -eq "network"){
                if($NatRule.DestAddress.endswith("ip")){$NatRule.DestAddress= "{0} Adress" -f $($Interfaces | Where-Object { $_.Name -eq $NatRule.DestAddress.split("ip")[0]})}
                else{$NatRule.DestAddress= "{0} Net" -f $($Interfaces | Where-Object { $_.Name -eq $NatRule.DestAddress})}
            }

        }

        return $NatRules
    }
}

function Get-PFfirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $FirewallRules = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFfirewallRule
        $Interfaces = $InputObject | Get-PFInterface
        $FirewallSeperator = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFFirewallseparator
        # replace the text of the gateway with its actual object
        ForEach($FirewallRule in $FirewallRules){
            # we need to make sure that the interface is an array and not just a string.
            # this is proof of concept method only, next step is to make it more generic and
            # try to check the property type in the ConvertTo function
            if($FirewallRule.Interface.GetType() -eq [string]){
                $FirewallRule.Interface = $FirewallRule.Interface -split ","
            }

            # replace the interface text by it's object
            ForEach($Interface in $FirewallRule.Interface){
                $Interface = $Interfaces | Where-Object { $_.Name -eq $Interface }
            }

            if($FirewallRule.SourceType -eq "network"){
                if($FirewallRule.SourceAddress.endswith("ip")){$FirewallRule.SourceAddress= "{0} Adress" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.SourceAddress.split("ip")[0]})}
                else{$FirewallRule.SourceAddress= "{0} Net" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.SourceAddress})}
                }
            if($FirewallRule.DestType -eq "network"){
                if($FirewallRule.DestAddress.endswith("ip")){$FirewallRule.DestAddress= "{0} Adress" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.DestAddress.split("ip")[0]})}
                else{$FirewallRule.DestAddress= "{0} Net" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.DestAddress})}
                }
            if($FirewallRule.log -eq " "){$FirewallRule.log = "Yes"}
        }

        return $FirewallRules
        #return $FirewallSeperator
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
        # construct URL and response parameters
        $URLTemplate = "##SCHEME##://##HOST####PORT##/xmlrpc.php"

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

        $URL = $URLTemplate `
                -replace '##SCHEME##', (($Server.NoTLS) ? 'http' : 'https') `
                -replace '##HOST##', $Server.Address `
                -replace '##PORT##', (($Server.Port) ? ":$($Server.Port)" : '')
                
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
            Write-Debug "The returned content-type was: $($Response.Headers.'Content-Type')"
            Write-Debug "The message from the server could not be converted to XML. This is what the server returned: $($Response.Content)" 
            Write-Debug "Your message to the server was: $($XMLRequest)"

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

        # maybe something happened, but we are able to use the system
        } catch {
            Write-Debug $_.Exception.Message
            Write-Debug $_.ScriptStackTrace
        }

        return $true
    }    
}

## BEGIN OF CONTROLLER LOGIC
Clear-Host

# TODO: insert logic from my master branch here to validate $Server and populate $PFServer object
$PFServer = [PFServer]@{
    Credential = $null
    Address = $Server
    Port = $null
    NoTLS = $NoTLS
    SkipCertificateCheck = $SkipCertificateCheck
}

# Warn the user if no TLS encryption is used
if($PFServer.NoTLS){
    Write-Warning "your credentials are transmitted over an INSECURE connection!"
}

# Test credentials before we continue. 
if(-not [string]::IsNullOrWhiteSpace($Username)){
    if(-not [string]::IsNullOrWhiteSpace($InsecurePassword)){
        $Password = ConvertTo-SecureString -String $InsecurePassword -AsPlainText -Force
        $PFServer.Credential = New-Object System.Management.Automation.PSCredential($Username, $Password) 

    } else {
        $PFServer.Credential = Get-Credential -UserName $Username
    }
}
while(-not (Test-PFCredential -Server $PFServer)){ $PFServer.Credential = Get-Credential }

# Get all config information so that we can see what's inside
$XMLConfig = Get-PFConfiguration -Server $PFServer
if(-not $XMLConfig){ exit }

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
    "portfwd" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFnatRule | Format-table *"
    }    
    "Firewall" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFfirewallRule | Format-table * -AutoSize" 
    } 
     

}

# execute requested flow
try{
    if(-not $Flow.ContainsKey($Service)){  Write-Host "Unknown service '$Service'" -ForegroundColor red; exit 2 }
    if(-not $Flow.$Service.ContainsKey($Action)){ Write-Host "Unknown action '$Action' for service '$Service'" -ForegroundColor red; exit 3 }

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $XMLConfig


} catch {
    Write-Error $_.Exception
    exit 1    
}
