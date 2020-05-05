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
# TODO: make this a bit nicer, with error handling and stuff
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
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)][PFServer]$InputObject,
        [Parameter(Mandatory=$true)]$PFObjectType
    )

    begin{
        $Object = (New-Object -TypeName $PFObjectType)        
        $PropertyMapping = $Object::PropertyMapping

        # to make the names a bit clearer, use PFType, PFTypeProperties and PFTypePropertyMapping
        # this because in the parsing, it otherwise gets confusing since there are a lot of variables refering to some $object... thing
        $PFType = (New-Object -TypeName $PFObjectType)
        $PFTypeProperties = ($PFType | Get-Member -MemberType properties).Name
        $PFTypePropertyMapping = $PFType::PropertyMapping

        $Collection = New-Object System.Collections.ArrayList        
    } 

    process { 
        # make double sure the PFServer $inputObject has the configuration stored inside. It most likely already has the configuration,
        # which makes it scenario 2 for Get-PFConfiguration and it will return the $InputObject unaltered.
        $InputObject = $InputObject | Get-PFConfiguration
        
        $ObjectToParse = $InputObject.PSConfig
        foreach($XMLPFObj in ($Object::section).Split("/")){
            $ObjectToParse = $ObjectToParse.$XMLPFObj
        }
        if(-not $ObjectToParse){ return }

        # $ObjectToParse can be one of two types: a hashtable or an array. They require a slightly different approach of iteration.
        # This IF statement is to see if the $ObjectToParse is a array of object (this happens with the interface), if it is a array, we need to loop to each item to Get- it's value's
        $ObjectsInHashtable =$ObjectToParse.GetType() -eq [hashtable]

        # To enable a single and structured approach, we need to make the hashtable key (often the Name property, but not always) 
        # available in the value (value always is a hashtable). This makes sure we can use one iterable function to iterate over all objects. 
        # The idea is that one entry in the array/hashtable equals to one PF* object, so after this, we can loop through the array and do the conversion.
        # The hashtable key will be made available in the array as "_key"
        if($ObjectsInHashtable){
            $ObjectToParse.GetEnumerator() | ForEach-Object {
                if($_.Value."_key"){ return } # this is how to simulate "continue" in a ForEach-Object block, see http://stackoverflow.com/questions/7760013/ddg#7763698
                if($_.Value.PSObject.Methods.Name -notcontains "Add" ){ return }

                $_.Value.Add("_key", $_.Key)
            }
        }

        # now iterate over all objects and convert them
        $ObjectToParse.GetEnumerator() | ForEach-Object {
            # the last step of the process will be to create a new object. We need a container with the property values for the PF* object
            # so that we can splat them into the New-Object cmdlet later
            $PFObjectProperties = @{} 

            # iterate over all properties that are defined in the PF* object. 
            # find the property value based on the property mapping (if that exists) or assume the property name in $ObjectToParse is the 
            # same as in the PF* object if no mapping is defined, i.e. $PFTypeProperty
            foreach($PFTypeProperty in $PFTypeProperties){
                # set the default property value: null. We have:
                # - $PropertyValue: the uncasted property value
                # - $PropertyTypedValue: $PropertyValue casted to another PF* object, like PFInterface or PFGateway
                $PropertyValue = $PropertyValues = $PropertyTypedValue = $PropertyTypedValues = $null

                # do the mapping from PFTypeProperty to $ObjectToParse property. Retain the XML in the name to indicate clearly it refers
                # to the property name as returned by the XML-RPC request. 
                # if no mapping exists, assume the propertyname in the $ObjectToParse is the same as in the PF* object
                $XMLProperty = ($PFTypePropertyMapping.$PFTypeProperty) ? $PFTypePropertyMapping.$PFTypeProperty : $PFTypeProperty.ToLower()

                # assign the uncasted property value. If there is a / in the property name, it means that it should be iterated one level deeper.
                # unlimited deep nesting levels are supported.
                # if $_ is a hashtable, the value is in $_.Value.$XMLProperty, when it's an array it's in $_.$XMLProperty
                $XMLPropertyTree = $XMLProperty.Split("/")
                $XMLPropertyRoot = $XMLPropertyTree | Select-Object -First 1

                # first handle the root. We need to separate this because it's value comes form the array/hashtable $_
                $PropertyValues = ($_.Value) ? $_.Value.$XMLPropertyRoot : $_.$XMLPropertyRoot

                # now handle all lower levels (if none exists this step will be effectively skipped)
                foreach($XMLProperty in ($XMLPropertyTree | Select-Object -Skip 1)){
                    if(-not ($PropertyValues -and $PropertyValues.$XMLProperty)) { break }

                    $PropertyValues = $PropertyValues.$XMLProperty
                }
                
                # if the $PropertyValue equals $null, we do not have to process anything. It doesn't need to be added to the 
                # $PFObjectProperties hashtable, since $null is the implicit default value. no need to make that explicit.
                if([string]::IsNullOrEmpty($PropertyValues)){ continue }

                # since the $ObjectToParse is the parsed XML-RPC message, all the values are (supposed to) XMLElements.
                # we need to replace the XMLElement by its (string) actual value. All other adjustments can be done here as well.
                $PropertyValues = $PropertyValues | ForEach-Object { ($_.PSObject.Properties.Name -contains "InnerText") ? $_.InnerText : $_ }

                # we need to support two scenario's now: one where the $PropertyValue is a single item and one where it's an array of items
                # in order to maintain only one workflow, we will make sure it is an array of items (or array of one item). 
                # after typecasting the propertyvalues later in this cmdlet, we will convert again to single item if necessary.
                if(($PropertyValues.GetType()).BaseType -ne [array]){ $PropertyValues = @($PropertyValues) }

                # next step is to cast the $PropertyValue to the required type as specified in the PF* object
                # if we omit this step, we will get an exception when trying to instantiate the object
                # to enable that, let's gather the property definition to see where to cast to
                $PropertyDefinition = ($PFType | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $PFTypeProperty }).Definition
                $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                $PropertyIsCollection = $PropertyDefinition.Contains("[]")

                # TODO: the || and space splitted items will be not necessary anymore after PFAlias has been refactored to contain PFAliasEntries
                #       known issue: PFAlias property Detail is split on space, which should not happen. BUT, properties Address/Detail need to be in their own object anyway
                # If the property is (should be) a collection but contains only one item, we might need to split them.
                if($PropertyIsCollection -and ($PropertyValues.Count -eq 1)){
                    $PropertyValue = $PropertyValues | Select-Object -First 1

                    foreach($Delimeter in @("||", ",", " ")){
                        if($PropertyValue.Contains($Delimeter)){
                            $PropertyValues = $PropertyValue.split($Delimeter)
                            break # only split on 1 delimeter, so stop after one succesful split and do NOT continue with the other possible delimeters
                        }
                    }
                }  

                $PropertyTypedValues = New-Object System.Collections.ArrayList
                foreach($PropertyValue in $PropertyValues){
                    switch($PropertyType){
                        # TODO: PFGateway
                        #"PFGateway"     { $PropertyTypedValue = $InputObject | Get-PFGateway -Name $Item } 
                        "PFInterface"   { $PropertyTypedValue = $InputObject | Get-PFInterface -Name $PropertyValue }
                        "bool"          { $PropertyTypedValue = ([bool]$PropertyValue -or ($PropertyValue -in ('yes', 'true', 'checked'))) }
                        default         { $PropertyTypedValue = $PropertyValue }
                    }

                    $PropertyTypedValues.Add($PropertyTypedValue) | Out-Null
                }

                # at this point, the:
                #   - $PropertyTypedValues contains an array with all the $PropertyTypedValue items
                #   - $PropertyTypedValue contains the casted version of the last $Item
                #
                # if $PropertyIsCollection we will add the array to the $PFObjectProperties hashtable
                # if the value should be singular (e.g. $PropertyIsCollection is false), we will add the $PropertyTypedValue
                # this behavior mimics that the last item overwrites earlier items (if any). 
                $PFObjectProperties.$PFTypeProperty = ($PropertyIsCollection) ? $PropertyTypedValues : $PropertyTypedValue
            } # end loop through all PFTypeProperties

            # create the instance of PFType and add it to the collection
            $PFTypeInstance = New-Object -TypeName $PFObjectType -Property $PFObjectProperties
            $Collection.Add($PFTypeInstance) | Out-Null
        }

        <#
        if ($ObjectsInArray){
            write-host "IF"
            while($ObjectToParse[$index]){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                    $PropertyValue = $ObjectToParse[$index]
                    $PropertyTypedValue = $null

                    foreach($XMLProp in $XMLProperty.Split("/")){                    
                        $PropertyValue = $PropertyValue.$XMLProp
                    }
                    
                    If($PropertyValue -and ($PropertyValue.GetType() -eq [System.Xml.XmlElement])){
                        $PropertyValue = $PropertyValue.InnerText
                    }
                    # The else if is for when a propertyvalue is a array of strings
                    elseif($PropertyValue -and ($PropertyValue.GetType() -eq [System.Object[]])){
                        $PropertyArray = New-Object System.Collections.ArrayList
                        foreach($value in $PropertyValue){
                            $PropertyArray.add($value.Innertext) | out-null
                        }
                        $PropertyValue = $PropertyArray
                    }

                    # if($PropertyValue.string){$PropertyValue = $PropertyValue.string}
                    
                    $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                    $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                    $PropertyIsCollection = $PropertyDefinition.Contains("[]")
 
                    # TODO: make the typed conversion work with non-collections too :)
                    if($PropertyIsCollection -and $PropertyValue){
                        if($Property -eq "Detail"){$PropertyValue = $PropertyValue.Split("||")}
                        elseif($Property -eq "Address"){$PropertyValue = $PropertyValue.Split(" ")}
                        else{$PropertyValue = $PropertyValue.Split(",")}
                    
                        $PropertyTypedValue = New-Object System.Collections.ArrayList
                        ForEach($Item in $PropertyValue){
                            switch($PropertyType){
                                "PFInterface" {
                                    $PropertyTypedValue.Add(
                                        ($InputObject | Get-PFInterface -Name $Item)
                                    ) | Out-Null
                                }
                            }
                        }
                    
                    # obviously it should work for non-collections too. This screams for some refactoring, btw!
                    } elseif($PropertyValue){
                        switch($PropertyType){
                            "PFInterface" { $PropertyValue = $InputObject | Get-PFInterface -Name $PropertyValue } 
                        }
                    }

                    $Properties.$Property = ($PropertyTypedValue) ? $PropertyTypedValue : $PropertyValue
                }
                $Object = New-Object -TypeName $PFObjectType -Property $Properties
                $Collection.Add($Object) | Out-Null
                $index++
            }
        }

        # If $ObjectToParse isn't a array we use a slightily different way to Get- it's value's
        elseif($ObjectsInHashtable){
            write-host "Else"
#            foreach($key in $PFconfig.($Object::section).keys){
            foreach($key in $ObjectToParse.keys){
                $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                    $Property = $_.Name
                    $XMLProperty = ($PropertyMapping.$Property) ? $PropertyMapping.$Property : $Property.ToLower()
                    $PropertyValue = $PropertyTypedValue = $null

                    if($XMLProperty -eq $key){
                        $PropertyValue = $ObjectToParse
                    }
                    else{
                        $PropertyValue = $ObjectToParse.$key
                    }
                    foreach($XMLProp in $XMLProperty.Split("/")){
                        if($XMLProp -eq 'name'){
                            $PropertyValue = $key
                        }
                        else{
                            $PropertyValue = $PropertyValue.$XMLProp
                        }
                    }
                    
                    If($PropertyValue -and ($PropertyValue.GetType() -eq [System.Xml.XmlElement])){
                        $PropertyValue = $PropertyValue.InnerText
                    }
                    elseif($PropertyValue -and ($PropertyValue.GetType() -eq [System.Object[]])){
                        $PropertyArray = New-Object System.Collections.ArrayList
                        foreach($value in $PropertyValue){
                            $PropertyArray.add($value.Innertext) | out-null
                        }
                        $PropertyValue = $PropertyArray 
                    }
                    
                    $PropertyDefinition = ($Object | Get-Member -MemberType Properties | Where-Object { $_.Name -eq $Property }).Definition
                    $PropertyType = ($PropertyDefinition.Split(" ") | Select-Object -First 1).Replace("[]", "")
                    $PropertyIsCollection = $PropertyDefinition.Contains("[]")
                    
                    # TODO: make the typed conversion work with non-collections too :)
                    if($PropertyIsCollection -and $PropertyValue){
                        if($Property -eq "Detail"){$PropertyValue = $PropertyValue.Split("||")}
                        elseif($Property -eq "Address"){$PropertyValue = $PropertyValue.Split(" ")}
                        else{$PropertyValue = $PropertyValue.Split(",")}
                    
                        $PropertyTypedValue = New-Object System.Collections.ArrayList
                        ForEach($Item in $PropertyValue){
                            switch($PropertyType){
                                "PFInterface" {
                                    $PropertyTypedValue.Add(
                                        ($InputObject | Get-PFInterface -Name $Item)
                                    ) | Out-Null
                                } 
                            }
                        }

                    # obviously it should work for non-collections too. This screams for some refactoring, btw!
                    } elseif($PropertyValue){
                        switch($PropertyType){
                            "PFInterface" { $PropertyValue = $InputObject | Get-PFInterface -Name $PropertyValue } 
                        }
                    }
                    
                    If($PropertyValue -and ($PropertyValue.GetType() -eq [System.Xml.XmlElement])){
                        $PropertyValue = $PropertyValue.InnerText
                    }
                    $Properties.$Property = ($PropertyTypedValue) ? $PropertyTypedValue : $PropertyValue
                    
                }
            $Object = New-Object -TypeName $PFObjectType -Property $Properties
            $Collection.Add($Object) | Out-Null
            }
        
        
        
        
        } else {
            throw [System.ArrayTypeMismatchException]::new('Unexpected type for the iterable, expecting a hashtable or an array.')
        }
        #>

        
        # return the collection with PF* objects
        return $Collection
    }
}

function FormatXml {
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
    <#
    .SYNOPSIS
        Fetch the current configuration from a pfSense server via XML-RPC. Convert the XML-RPC answer to a Powershell object.
    
    .DESCRIPTION
        This function takes a PFServer object and adds to it the configuration for this server. 
        
        There are three scenario's which are supported by this function:
        1) The PFServer object has no XMLConfig saved
        2) The PFServer object has a XMLConfig saved already
        3) The PFServer object has a XMLConfig saved already but the user wants to have it refreshed

        Ad 1: 
        If there is no XML configuration in the PFServer object, it will be fetched from the pfSense as defined in the PFServer object.
        After fetching and validating the XML, it will be converted into a Powershell object for easier parsing by other functions.

        Ad 2:
        The supplied PFServer object already has a configuration stored inside. Do nothing and just return the PFServer object.

        Ad 3:
        For some reason the user suspects the saved configuration (if any) might be stale so it should be refreshed. It can do do so by setting
        the -NoCache flag to force scenario 1 to be executed after clearing the currently saved configuration.
    
    .PARAMETER Server
        The PFServer object to act on. This value can be passed by pipeline and multiple PFServer objects can be passed that way at once.

    .PARAMETER NoCache
        Switch to indicate that any saved configuration MUST be refreshed by querying the pfSense server

    #>
    [CmdletBinding()]
    [OutputType('PFServer')] 
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [Alias('Server')]
            [PFServer]$InputObject,
        [Parameter(Mandatory=$false)]
            [switch]$NoCache
    )
    
    process {
        # check for scenario 3, i.e. forced refresh of possibly stale cached configuration. 
        # Set both the XMLConfig and PSConfig properties to $null to force the Invoke-PFXMLRPCRequest to be executed
        if($NoCache){ $InputObject.XMLConfig = $InputObject.PSConfig = $null }

        # check if the XML configuration has been saved and is valid (scenario 2). If this is NOT the case (i.e. scenario 1), update the configuration.
        if((-not $InputObject.XMLConfig) -or ($InputObject.XMLConfig.GetType() -ne [XML])){
            try{
                $InputObject.XMLConfig = Invoke-PFXMLRPCRequest -InputObject $InputObject -Method 'exec_php' -MethodParameter 'global $config; $toreturn=$config;'
                $InputObject.PSConfig = ConvertFrom-Xml -InputObject $InputObject.XMLConfig

            } catch {
                # TODO: do some proper error handling here. Need to handle the exceptions that Invoke-PFXMLRPCRequest or ConvertFrom-XML can throw
                Write-Error $_.Exception.Message
                Write-Error $_.Exception
                exit 1
            }
        }

        return $InputObject
    }    
}

function Get-PFInterface {
    <#
    .SYNOPSIS 
        Get a PFInterface object for each of the interfaces that are available in the pfSense

    .DESCRIPTION
        Get-PFInterface is one of the more extensive Get-PF* functions, since there are a couple of special things that need to happen
        First, it gets the interfaces as defined in the pfSense configuration. So far, that's very standard behavior.
        Secondly, it adds some interfaces that are not explicitly defined but nonetheless exist in the pfSense server, e.g. lo0 (local loopback)

    .PARAMETER Server
        Alias for InputObject, accepts the pipeline input. This should be a PFServer object.

    .PARAMETER Name
        Optional parameter to filter by interface name. 
    #>
    [CmdletBinding()]
    [OutputType([PFInterface[]])]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject,
        [Parameter(Mandatory=$false)][string]$Name
    )   
    process { 
        # TODO: for performance reasons, you might want to consider a check if the interfaces exist already. In that case, you can simply return the existing version already.
        #       without that addition is might perform a few extra steps every time, but it's very unlikely that it will be a bottleneck.

        # Since we will add some ephemeral interfaces later on, the $Interfaces array needs to be extensible and hence be explictly defined as ArrayList first
        $Interfaces = New-Object System.Collections.ArrayList

        # Retrieve the explicitly defined interfaces from the pfSense configuration and add them to the $Interfaces collection.  
        $InterfacesFromConfig = $InputObject |  ConvertTo-PFObject -PFObjectType "PFInterface"
        $InterfacesFromConfig | ForEach-Object { $Interfaces.Add($_) | Out-Null }
        
        # add the IPv6 LinkLocal name and description so these can be translated
        $InterfacesFromConfig.GetEnumerator() | ForEach-Object {
            $Properties = @{
                Name = "_lloc{0}" -f $_.Name
                Description = "{0}IpV6LinkLocal" -f (($_.Description) ? $_.Description : $_.Name)
            }
             
            $EphemeralInterface = New-Object -TypeName "PFInterface" -Property $Properties
            $Interfaces.Add($EphemeralInterface) | Out-Null    
        }

        # there is also a number of implicitly defined interfaces that do not appear in the configuration
        # these are the Link Local, loopback and the IPv6 interfaces. 
        # there is also a special interface All, which is a reference to all interfaces. This one is used for example in service configurations
        # that should listen on all interfaces and is functionally equivalent to :: . 
        # However, in the configuration for these services (e.g. DNS server) it appears as string "all"
        # We need to manually create these "static interfaces" to satisfy the type definition/conversion on the PF* where an interface is defined
        # as [PFInterface]$Interface (or [PFInterface[]]$Interface in some cases.)
        (@{ all = 'All'; lo0 = 'Loopback' }).GetEnumerator() | ForEach-Object {
            $EphemeralInterface =  New-Object -TypeName "PFInterface" -Property @{ Name = $_.Key; Description = $_.Value }
            $Interfaces.Add($EphemeralInterface) | Out-Null
        }

        # return section
        # return all the interfaces if no $Name parameter was given
        if([string]::IsNullOrWhitespace($Name)){
            return $Interfaces
        
        # return the $Interfaces, filtered by Name -eq $Name
        } else {           
            return ($Interfaces | Where-Object { $_.Name -eq $Name })
        }
    }
        
}
function Get-PFAlias {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType "PFAlias"
    }
}

function Get-PFDHCPd {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType "PFDHCPd"
    }
} 

function Get-PFdhcpStaticMap {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType "PFDHCPStaticMap"
    }
}
function PrintPFdhcpStaticMap {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $Object = (New-Object -TypeName "PFdhcpStaticMap")
        $Collection = New-Object System.Collections.ArrayList
        foreach($Staticmap in $InputObject.WorkingObject){
            $indexStaticMap = 0 
            $Properties = @{}
                while($Staticmap.MACaddr[$indexStaticMap]){
                    $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                        $Property = $_.Name
                        if($Property -eq "interface"){$PropertyValue = $Staticmap.interface}
                        else{
                            try {$PropertyValue = $Staticmap.$Property[$indexStaticMap]}
                            catch{$PropertyValue = $Staticmap.$Property}
                        }
                        $Properties.$Property = $PropertyValue
                    }
                    $Object = New-Object -TypeName "PFdhcpStaticMap" -Property $Properties
                    $Collection.Add($Object) | Out-Null
                    $indexStaticMap++
                }
        }
        $InputObject.WorkingObject = $Collection
        return $InputObject | out-null
    }
}

function Get-PFFirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType "PFfirewallRule"
    }
}
function PrintPFFirewallRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
            foreach($Rule in $InputObject.WorkingObject){
                ("Source","Destination") | foreach {
                    $Rule.$($_+"Port") = ($Rule.$_.Port) ? $Rule.$_.Port.InnerText : "any"

                    if($Rule.$_.Contains("any")){
                        $Rule.$($_+"address") = "any"

                    } elseif($Rule.$_.Contains("address")) {
                        $Rule.$($_+"address") = $Rule.$_.address.InnerText

                    } elseif($Rule.$_.Contains("network")){
                    if($($Rule.$_.network.InnerText).endswith("ip")){
                        $Rule.$($_+"address") = ("{0} address" -f $Rule.$_.network.InnerText.split("ip")[0])
                    }
                        else{$Rule.$($_+"address") = ("{0} network" -f $Rule.$_.network.InnerText)}
                    }
                }
            }
        return $InputObject | out-null
    }
}

function Get-PFGateway {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType "PFGateway"
    }
}
function Get-PFNATRule {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][PFServer]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType "PFnatRule"
    }

}
function Get-PFStaticRoute {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType  "PFStaticRoute"
    }
}

function Get-PFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        $InputObject | ConvertTo-PFObject -PFObjectType  "PFUnbound"
    }
} 

function PrintPFUnbound {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process {
        $Properties = @{}
        $Object = New-Object -TypeName "PFUnbound" -Property $Properties
        foreach($Rule in $InputObject.WorkingObject){
            $Object | Get-Member -MemberType properties | Select-Object -Property Name | ForEach-Object {
                if($Rule.($_.name)){$Properties.($_.name) = $Rule.($_.name)}
            }
        }
        if(-not $Properties.port){$Properties.port = "53"}
        if(-not $Properties.sslport){$Properties.sslport = "853"}
        $Object = New-Object -TypeName "PFUnbound" -Property $Properties
        $InputObject.WorkingObject = $Object 
        return $InputObject | out-null
    }
} 

function Get-PFunboundHost {
    [CmdletBinding()]
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)][Alias('Server')][psobject]$InputObject)
    process { 
        $InputObject | ConvertTo-PFObject -PFObjectType "PFunboundHost"
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
        Write-Debug ($XMLRequest | FormatXml ) -Verbose 

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

function TestPFCredential {
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

$PFServer = New-Object PFServer -Property @{
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
    while(-not (TestPFCredential -Server $PFServer)){ $PFServer.Credential = Get-Credential }

} catch [System.TimeoutException] {
    Write-Error -Message $_.Exception.Message
    exit 4

} finally {
    Write-Progress -Activity "Testing connection and your credentials" -Completed
}

# Get- all config information so that we can see what's inside
$PFServer = ($PFServer | Get-PFConfiguration -NoCache)

# test objects
# make a clear visual distinction between this run and the previous run
#<#
1..30 | ForEach-Object { Write-Host "" }

# works
Write-Host "Known interfaces:" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFInterface | Format-table *

# works
Write-Host "LAN interface:" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFInterface -Name "lan" | Format-table *

# works
# TODO: separate each address/detail in a separate child object, like PFAliasEntry or something like that. Each PFAlias should then contain a collection of these.
Write-Host "Registered aliases:" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFAlias | Format-table *

# works
Write-Host "Registered DHCPd servers" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$DHCPdServers = $PFServer | Get-PFDHCPd
$DHCPdServers | Format-table *
$DHCPdInterfaceType = ($DHCPdServers | Select-Object -First 1 -ExpandProperty Interface).GetType()
$DHCPdInterfaceIsPFInterface = $DHCPdInterfaceType -eq [PFInterface]
Write-Host ("Typecheck of Interface property of DHCPd server 1: {0}" -f $DHCPdInterfaceType) -ForegroundColor ($DHCPdInterfaceIsPFInterface ? "Green" : "Red")

# TODO: a lot
Write-Host "Registered static DHCP leases" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFDHCPStaticMap | Format-table *


# TODO: source/destination
Write-Host "All firewall rules" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
# TODO: if you want to convert System.Collections.Hashtable into something more meaningful (display only), do it here
#       obviously creating a Write-PFFirewallRule function would be an even better idea :)
#       DO NOT change it in the ConvertTo-PFObject function, since that will really complicate the reverse operation (changing and uploading the rule)
$PFServer | Get-PFFirewallRule | Select-Object -ExcludeProperty Source, Destination | Format-table *

# works
Write-Host "Registered gateways" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFGateway | Format-table *

# TODO: a lot
Write-Host "All NAT rules" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFNATRule | Format-table *

# TODO: mapping to PFGateway object
Write-Host "All static routes" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFStaticRoute | Format-table *

# TODO: mapping to PSObject 
Write-Host "DNS server settings" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFUnbound | Format-table *

# TODO: mapping to PSObject
Write-Host "DNS host overrides" -NoNewline -BackgroundColor Gray -ForegroundColor DarkGray
$PFServer | Get-PFunboundHost | Format-table *

Write-Host "THE END" -BackgroundColor Gray -ForegroundColor DarkGray
exit;
#>

<# define the possible execution flows
$Flow = @{
    "alias" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFAlias; `$InputObject.WorkingObject | Format-Table *"#the star makes the format table show more than 10 column's
    }

    "gateway" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFGateway; `$InputObject.WorkingObject | Format-Table *"
    }

    "interface" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFInterface; `$InputObject.WorkingObject | Format-Table *"
    }

    "StaticRoute" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFStaticRoute; `$InputObject.WorkingObject | Format-table *"
    }

    "dnsResolver" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFUnbound; `$InputObject | PrintPFUnbound; `$InputObject.WorkingObject | Format-table *"
    }    

    "dnsResolverHost" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFunboundHost; `$InputObject.WorkingObject | Format-table *"
    }   

    "portfwd" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFNATRule; `$InputObject.WorkingObject | Format-table *"
    }    
    "Firewall" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFFirewallRule; `$InputObject | PrintPFFirewallRule; `$InputObject.WorkingObject | Select-Object -ExcludeProperty Source, Destination | Format-table *" 
    } 
    "dhcpd" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFDHCPd; `$InputObject.WorkingObject | Format-table *" 
    } 
    "dhcpStaticMap" = @{
        "print" = "param(`$InputObject); `$InputObject | Get-PFdhcpStaticMap; `$InputObject | PrintPFdhcpStaticMap; `$InputObject.WorkingObject | Format-table * -autosize" 
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
#>