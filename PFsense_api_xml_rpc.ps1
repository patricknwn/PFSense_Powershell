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

class PFInterface {
    [string]$Name
    [string]$Interface
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
   
    begin {
        $PFInterfaces = New-Object System.Collections.ArrayList
    }

    process {
        Get-PFConfiguration -Server $PFObject -Section "interfaces" | 
            Select-XML -XPath "//param/value/struct/member" | 
                ForEach-Object {                    
                    try{
                        $AttributeMapping = @{
                            Interface = "if"
                            IPv4Address = "ipaddr"
                            IPv4Subnet = "subnet"
                            IPv4Gateway = "gateway"
                            IPv6Address = "ipaddrv6"
                            IPv6Subnet = "subnetv6"
                            IPv6Gateway = "gatewayv6"
                            Trackv6Interface = "track6-interface"
                            Trackv6PrefixId = "track6-prefix-id"
                            BlockBogons = "blockbogons"
                            Media = "media"
                            MediaOpt = "mediaopt"
                            DHCPv6DUID = "dhcp6-duid"
                            DHCPv6IAPDLEN = "dhcp6-ia-pd-len"

                        }

                        $If = [PFInterface]@{ Name = (Select-XML -Xml $_.Node -XPath "name").Node.InnerText }                        
                        ForEach($Attribute in $AttributeMapping.Keys){
                            $Node = Select-XML -Xml $_.Node -XPath "value/struct/member[name='$($AttributeMapping."$Attribute")']/value/*"

                            If($Node){ 
                                $If."$Attribute" = $Node.Node.InnerText 
                            }
                        }

                        [void]$PFInterfaces.Add($If)

                    } catch {
                        Write-Error $_.Exception.Message
                        Write-Error $_.ScriptStackTrace
                    }                    
                }

        return $PFInterfaces
    }

    end {
        #Write-Debug "Attach debugger here "
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

        # most likely reason for this error is that the returened message was invalid XML, probably because you messed up ;)
        } catch [System.Management.Automation.RuntimeException] {
            Write-Debug "The returned content-type was: $($Response.Headers.'Content-Type')"
            Write-Debug "The message from the server could not be converted to XML. This is what the server returned: $($Response.Content)" 
            Write-Debug "Your message to the server was: $($XMLRequest)"

        # unknow exception, let the user 
        } catch {
            Write-Error $_.Exception.Message
            Write-Error $_.ScriptStackTrace
        }
    }
}
function Test-Credential {
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
        } catch [System.Security.Authentication.InvalidCredentialException],[System.Security.AccessControl.PrivilegeNotHeldException] {
            Write-Debug $_.Exception.Message
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

$PFObject = [psobject]@{
    Credential = $null
    Host = "10.10.10.5"
    Port = 443
    NoTLS = $false
    SkipCertificateCheck = $true
    SkipConnectionTest = $false    
}

# Warn the user if no TLS encryption is used
if($PFObject.NoTLS){
    Write-Warning "WARNING: your credentials are transmitted in over an INSECURE connection!"
}

# Test credentials before we continue. 
if(-not [string]::IsNullOrWhiteSpace($Username)){
    if(-not [string]::IsNullOrWhiteSpace($InsecurePassword)){
        $Password = ConvertTo-SecureString -String $InsecurePassword -AsPlainText -Force
        $PFObject.Credential = New-Object System.Management.Automation.PSCredential($Username, $Password) 

    } else {
        $PFObject.Credential = Get-Credential -UserName $Username
    }
}
while(-not (Test-Credential -Server $PFObject)){ $PFObject.Credential = Get-Credential }

# We have now tested credentials, let's get some stuff
$Interfaces = Get-PFInterface -Server $PFObject

# Print all interfaces
$Interfaces | Format-Table

# Get the if for LAN:
$IFLAN = $Interfaces | Where-Object { $_.Name -eq 'LAN' } | Select-Object -First 1
Write-Output "LAN has interface $($IFLAN.Interface)"


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