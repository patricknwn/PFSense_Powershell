# $server = "192.168.0.1" ; $username = "Admin" ; $InsecurePassword = "pfsense"

Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='The Server address')] [String] $Server,
    [Parameter(Mandatory=$false, Position=1,HelpMessage='The Username')] [string] $Username,
    [Parameter(Mandatory=$false, Position=2,HelpMessage='The Password')] [string] $InsecurePassword,
    [Parameter(Mandatory=$false, Position=3,HelpMessage='The service you would like to talke to')] [PSObject] $service,
    [Parameter(Mandatory=$false, Position=4,HelpMessage='The action you would like to do on the service')] [PSObject] $Action,
    [Switch] $NoTLS
    )

. .\man.ps1

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
unbound = dnsresolver
cert = cerificates
#>

class PFInterface {
    [string]$Name
    [string]$Interface
    [string]$Description
    [string]$IPv4Address    # should be [ipaddress] object, but that's for later
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

class PFGateway{
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

class PFalias{
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

function ConvertTo-PFObject {
    [CmdletBinding()]
    param (
        ## The XML-RPC response message
        [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
            [XML]$XML,
        # The object type (e.g. PFInterface, PFStaticRoute, ..) to convert to
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [ValidateSet('PFInterface','PFStaticRoute','PFGateway','PFalias')]
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

            # ForEach($Property in $PropertyMapping.Keys){
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

                $Properties.$Property = $PropertyValue
            }

            $Object = New-Object -TypeName $PFObjectType -Property $Properties
            [void]$Collection.Add($Object)
        }

        if($Collection.Count -lt 1){
            $Collection.Add($Object)
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
            [Alias('InputObject')]
            [psobject]$Server,
        [Parameter(Mandatory=$false, HelpMessage="The section of the configuration you want, e.g. interfaces or system/dnsserver")][string]$Section        
    )
    
    begin {
        if(-not [string]::IsNullOrWhiteSpace($Section)){
            $Section = $Section -split "/" | Join-String -Separator "']['" -OutputPrefix "['" -OutputSuffix "']"
        }
    }
    
    process {        
        return Invoke-PFXMLRPCRequest -Server $Server -Method 'exec_php' -MethodParameter ('global $config; $toreturn=$config{0};' -f $Section)
    }    
}

function Get-PFInterface {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [psobject]$Server
    )
   
    process {
        return Get-PFConfiguration -Server $PFServer -Section "interfaces" | ConvertTo-PFObject -PFObjectType PFInterface
    }
}

function Get-PFStaticRoute {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [psobject]$Server
    )

    process {
        Get-PFConfiguration -Server $PFServer -Section "staticroutes/route" | ConvertTo-PFObject -PFObjectType PFStaticRoute
    }
}

function Get-PFGateway {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [psobject]$Server
    )

    process {
        $Gateways = Get-PFConfiguration -Server $PFServer | ConvertTo-PFObject -PFObjectType PFGateway
        $Interfaces = Get-PFInterface -Server $PFServer

        ForEach($Gateway in $Gateways){
            $Gateway.Interface = $Interfaces | Where-Object { $_.Name -eq $Gateway.Interface }
        }

        return $Gateways
    }
}

function Get-PFalias {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('InputObject')]
            [psobject]$Server
    )

    process {
        $Aliases = Get-PFConfiguration -Server $PFServer -Section "aliases/alias" | ConvertTo-PFObject -PFObjectType PFalias 
        ForEach($Alias in $Aliases){
            $Alias.Address = $_.Address -split " "            
        }
        
        return $Aliases
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
            [psobject]$Server,
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
        $URLTemplate = "##SCHEME##://##HOST##:##PORT##/xmlrpc.php"

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
                -replace '##HOST##', $Server.Host `
                -replace '##PORT##', (($Server.Port) ? $Server.Port : '')
                
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
$PFServer = [psobject]@{
    Credential = $null
    Host = $Server
    Port = $null
    NoTLS = $NoTLS
    SkipCertificateCheck = $true
    SkipConnectionTest = $false    # TODO: implement (is this necessary?)
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

# We have now tested credentials, let's get some stuff
$PFServer | Get-PFInterface | Format-Table

# get the gateway's and convert the interface name to the user defined interface name
Get-PFGateway -Server $PFServer | Format-Table



$aliasses = Get-PFalias -Server $PFServer
$aliasses | Format-Table
 
$alias_print | format-table
#$aliasses | %{$_.address.split(" ");$_.detail.split("||") }

# Function Printe_route{
# # PFsense_api_xml_rpc.ps1 -server '192.168.0.1' -username 'admin' -Password 'pfsense' -service route -Action print -NoTLS
#     $php_command = "global `$config; `$toreturn=`$config['staticroutes'];"
#     $Data = [XML]$(Get-PFConfiguration -php_command $php_command).Content
#     Write-Host "Static routes are:" -BackgroundColor White -ForegroundColor Black
#     Write-Host "Network : Gateway : Description`n`r" -BackgroundColor White -ForegroundColor Black
#     $staticroutes = $($Data | Select-Xml -XPath "/methodResponse/params/param/value/struct/member/value/array/data/value")
#     $routeindex = 0
#     try{
#         if($staticroutes[$routeindex]){
#             while($staticroutes[$routeindex]){
#                 "{0} : {1} : {2}" -f`
#                 $staticroutes[$routeindex].Node.struct.member.value[0].string,`
#                 $staticroutes[$routeindex].Node.struct.member.value[1].string,`
#                 $staticroutes[$routeindex].Node.struct.member.value[2].string
#                 $routeindex++
#             }
#         }
#         else{"{0} : {1} : {2}" -f $staticroutes.Node.struct.member.value[0].string,$staticroutes.Node.struct.member.value[1].string,$staticroutes.Node.struct.member.value[2].string}
#     }catch{Write-host "No Static routes Found"}
# }

# function  print_interface {
#     $php_command = "global `$config; `$toreturn=`$config['interfaces'];"
#     $Data = [XML]$(Get-PFConfiguration -php_command $php_command).Content
#     Write-Host "Interfaces are:" -BackgroundColor White -ForegroundColor Black
#     Write-Host "Name : Gateway : Description`n`r" -BackgroundColor White -ForegroundColor Black
#     $interfaces = $data.methodResponse.params.param.value.struct.member
#     $interfaces[0].value.struct.member[0].name
#     $interindex = 0
#     try{
#         if($interfaces[$interindex].name){
#             while($interfaces[$interindex].name){
#                 "{0} : {1} : {2}" -f`
#                 $interfaces[$interindex].name,`
#                 $interfaces[$interindex].name,`
#                 $interfaces[$interindex].name
#                 $interindex++
#             }
#         }
#         else{"{0} : {1} : {2}" -f $interfaces.name,$interfaces.name,$interfaces.name}
#     }catch{Write-host "No Interfaces found"}
# }


#TODO: use a nicer structure, probably hashtables :)
# $Actions = @{ trigger = [ScriptBlock]::Create("Write-Host -Message 'WOW'") }
# Invoke-Command $Actions.trigger
#
# if (-not $service -or $service -eq "Help" -or $service -eq "H"){$HelpMessageheader
#     $manall
#     exit}
# elseif (-not $action -or $action -eq "Help" -or $action -eq "H"){
#     if($service -eq "route"){$manroute ; exit}
#     elseif($service -eq "Interface"){$manint ; exit}
#     elseif($service -eq "Gateway"){$manGateway ; exit}
#     elseif($service -eq "dnsresolver"){$mandnsresolver ; exit}
#     elseif($service -eq "portfwd"){$manportfwd ; exit}
#     elseif($service -eq "Alias"){$ManAlias ; exit}
#     elseif($service -eq "VIP"){$ManVIP ; exit}
#     elseif($service -eq "Firewall"){$ManFirewall ; exit}
#     }


# if ($service -eq "route"){
#     if ($action -eq "print"){Printe_route}
#     elseif ($action -eq "add"){add_route}
#     elseif ($action -eq "delete"){delete_route}  
# }
# elseif ($service -eq "Interface"){
#     if ($action -eq "print"){print_interface}
# }
# elseif ($service -eq "Gateway"){
#     if ($action -eq "print"){print_Gateway}
#     elseif ($action -eq "add"){add_Gateway }
#     elseif ($action -eq "delete"){delete_Gateway}
#     elseif ($action -eq "default"){default_Gateway}
# }
# elseif ($service -eq "dnsresolver"){
#     if ($action -eq "print"){print_dnsresolver}
#     elseif ($action -eq "UploadCustom"){UploadCustom_dnsresolver}
#     elseif ($action -eq "addhost"){addhost_dnsresolver}
#     elseif ($action -eq "Deletehost"){Deletehost_dnsresolver}
#     elseif ($action -eq "adddomain"){adddomain_dnsresolver}
#     elseif ($action -eq "deletedomain"){deletedomain_dnsresolver}
# }
# elseif ($service -eq "portfwd"){
#     if ($action -eq "print"){print_portfwd}
#     elseif ($action -eq "Add"){add_portfwd}
#     elseif ($action -eq "Delete"){Delete_portfwd}
# }
# elseif ($service -eq "Alias"){
#     if ($action -eq "print"){print_Alias}
#     elseif ($action -eq "PrintSpecific"){SpecificPrint_Alias}
#     elseif ($action -eq "add"){add_Alias}
#     elseif ($action -eq "delete"){delete_Alias}
#     elseif ($action -eq "addvalue"){addvalue_Alias}
#     elseif ($action -eq "deletevalue"){deletevalue_Alias}
# }
# elseif ($service -eq "Vip"){
#     if ($action -eq "print"){print_Vip}
#     elseif ($Action -eq "add"){add_Vip}
#     elseif ($Action -eq "delete"){delete_Vip}
# }
# elseif ($service -eq "Firewall"){
#     if ($action -eq "print"){print_Firewall}
#     elseif ($action -eq "add"){addrule_Firewall}
# }
# else{"Dit not find {0} please use `"-Server '' -Username '' -Password '' Help`" to see which ones are supported" -f $service}
# # for example, fetch all the DNS servers
# #[XML]$response.Content | Select-XML -XPath "//member[name='dnsserver']//string" | ForEach-Object { $_.Node.'#text' }

# # reduce the output to only the requested section:
# #$php_command = "global `$config; `$toreturn=`$config['system']['staticroutes'];"
# #$request_body = "<?xml version='1.0' encoding='iso-8859-1'?><methodCall><methodName>pfsense.exec_php</methodName><params><param><value><string>$php_command</string></value></param></params></methodCall>"

# #$response = Invoke-Webrequest  -UseBasicParsing -Authentication basic -Credential $pfsense_credentials -AllowUnencryptedAuthentication `
# #    -ContentType 'text/xml' `
# #    -Uri ("http://{0}/xmlrpc.php" -f $server) `
# #    -Method POST `
# #    -Body $request_body

# # for example, fetch all the DNS servers
# #[XML]$response.Content | Select-XML -XPath "//string" | ForEach-Object { $_.Node.'#text' }
