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
    [Parameter(Mandatory=$true, HelpMessage='The pfSense network address (DNS or IP)')] [string] $Server,
    [Parameter(Mandatory=$false, HelpMessage='The Username')] [string] $Username,
    [Parameter(Mandatory=$false, HelpMessage='The Password')] [string] $InsecurePassword,
    [Parameter(Mandatory=$false, HelpMessage='The service you would like to talke to')] [string] $Service,
    [Parameter(Mandatory=$false, HelpMessage='The action you would like to do on the service')] [string] $Action,
    [Switch] $NoTLS,
    [switch] $SkipCertificateCheck
    )


# dotsource the classes
. .\classes.ps1

function ConvertTo-PFObject {
    [CmdletBinding()]
    param (
        ## The XML-RPC response message
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [XML]$XMLConfig,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName = $true)]
            [PFServer]$Server,
        # The object type (e.g. PFInterface, PFStaticRoute, ..) to convert to
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [ValidateSet('PFInterface','PFStaticRoute','PFGateway','PFAlias',
                         'PFUnbound','PFNATRule','PFFirewallRule','PFFirewallSeparator')]
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
        $XMLSection = Select-Xml -Xml $XMLConfig -XPath '/methodResponse/params/param/value'
        ForEach($Subsection in $($Section -split '/')){
            $XMLSubsection = Select-Xml -XML $XMLSection.Node -XPath "./struct/member[name='$Subsection']/value"
            if($XMLSubsection){ $XMLSection = $XMLSubsection }
        }

        # Two XPath to get each individual item:
        #   XPath: ./struct/member (for associative array in the original PHP code)
        #   XPath: ./array/data/value (for index-based array in the original PHP code)
        $XMLObjects = Select-Xml -XML $XMLSection.Node -XPath "./struct/member | ./array/data/value"
        ForEach($XMLObject in $XMLObjects){    
            $XMLObject = [XML]$XMLObject.Node.OuterXML # weird that it's necessary, but as its own XML object it works           
            $Properties = @{}

            # loop through each property of $Object. We're interesed in the name only in order to create the hashtable $Properties
            # that we then later will use to splat into the object creation.
            $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                # the $Property is the property name, by default that is the same property name as in the XML document.
                # however, that is not always the case and those exceptions are defined in the [PF...]::PropertyMapping hashtable
                # if there is such an exception (e.g. $PropertyMapping.$Property has a value), we will use its value instead of the default
                # the XML has only lowercase property names, to that's why we convert $Property to lowercase
                $Property = $_.Name
                $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                $PropertyValue = $null
                $PropertyTypedValue = $null

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

                # let's inspect the property definition to see if we need to make any adjustments. Some adjustment that might be required:
                # - create a collection from a comma-separated string
                # - explicitly cast the value to a different object type
                $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                $PropertyIsCollection = $PropertyDefinition.Contains("[]")
                
                # if the property type is a collection, make sure the $PropertyValue is actually a collection. 
                # In the XML message, things we want to have as collection are separated by comma
                if($PropertyIsCollection){
                    $PropertyValue = $PropertyValue.Split(",")
                }

                # handle the conversion to our custom objects. For all other objects, we assume that the split
                # was sufficient. We might improve upon this later if necessary.
                # for now we support a few types only, but this might increase and need to be refactored if that's the case.
                $PropertyTypedValue = New-Object System.Collections.ArrayList
                ForEach($Item in $PropertyValue){
                    switch($PropertyType){
                        "PFInterface" {
                            $PropertyTypedValue.Add(
                                ($Server.Interfaces | Where-Object { $_.Name -eq $Item })
                            ) | Out-Null
                        }
                    }
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
                
                # add the property value to the hashtable. 
                # If there is a typed (converted) value, prefer that over the unconverted value
                $Properties.$Property = ($PropertyTypedValue) ? $PropertyTypedValue : $PropertyValue
            }

            # create the new object of type $PFObjectType (e.g. PFInterface, PFFirewallRule, ...)
            # We instantiate the object with values by splatting the properties hashtable
            # that we created before. 
            $Object = New-Object -TypeName $PFObjectType -Property $Properties
            $Collection.Add($Object) | Out-Null
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
            [PFServer]$InputObject,
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

        if($InputObject.XMLConfig -and $InputObject.XMLConfig.GetType() -eq [XML] -and [string]::IsNullOrWhiteSpace($Section)){             
            $XMLConfig = $InputObject.XMLConfig
        
        } else {
            $XMLConfig = Invoke-PFXMLRPCRequest -Server $InputObject -Method 'exec_php' -MethodParameter ('global $config; $toreturn=$config{0};' -f $Section)
        }
        
        #TODO: fetch only the relevant section if contains other sections too. Low prio.
        return $XMLConfig
    }    
}

function Get-PFInterface {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)   
    process { return $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFInterface -Server $InputObject }
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

function Get-PFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)

    process {
        $Unbound = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFunbound

        return $Unbound
    }
}

function Get-PFNATRule {
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

function Get-PFFirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)

    process {
        $FirewallRules = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFfirewallRule -Server $InputObject
        # $FirewallSeperator = $InputObject | Get-PFConfiguration | ConvertTo-PFObject -PFObjectType PFFirewallseparator
        # replace the text of the gateway with its actual object
        # ForEach($FirewallRule in $FirewallRules){
        #     if($FirewallRule.SourceType -eq "network"){
        #         if($FirewallRule.SourceAddress.endswith("ip")){
        #             $FirewallRule.SourceAddress= "{0} Adress" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.SourceAddress.split("ip")[0]})}
        #         else{$FirewallRule.SourceAddress= "{0} Net" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.SourceAddress})}
        #         }
        #     if($FirewallRule.DestType -eq "network"){
        #         if($FirewallRule.DestAddress.endswith("ip")){$FirewallRule.DestAddress= "{0} Adress" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.DestAddress.split("ip")[0]})}
        #         else{$FirewallRule.DestAddress= "{0} Net" -f $($Interfaces | Where-Object { $_.Name -eq $FirewallRule.DestAddress})}
        #         }
        #     if($FirewallRule.log -eq " "){$FirewallRule.log = "Yes"}
        # }

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

## BEGIN OF CONTROLLER LOGIC, should be moved to a different script later since debugging dotsourced file s*, leave it here for now.
Clear-Host

# TODO: insert logic from my master branch here to validate $Server and populate $PFServer object
$PFServer = [PFServer]@{
    Credential = $null
    Address = $Server
    NoTLS = $NoTLS
    SkipCertificateCheck = $SkipCertificateCheck
}

# Warn the user if no TLS encryption is used
if($PFServer.NoTLS){
    Write-Warning "your credentials are transmitted over an INSECURE connection!"
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
$PFServer.XMLConfig = Get-PFConfiguration -Server $PFServer
if(-not $PFServer.XMLConfig){ exit }

# We will have frequent reference to the [PFInterface] objects, to make them readily available
$PFServer.Interfaces = $PFServer | Get-PFInterface

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

    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Flow.$Service.$Action)) -ArgumentList $PFServer


} catch {
    Write-Error $_.Exception
    exit 1    
}
