Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='The Server address')] [PSObject] $Server,
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Username')] [PSObject] $Username,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Password')] [PSObject] $Password,
    [Parameter(Mandatory=$false, Position=3,HelpMessage='The service you would like to talke to')] [PSObject] $service,
    [Parameter(Mandatory=$false, Position=4,HelpMessage='The action you would like to do on the service')] [PSObject] $Action,
    [Parameter(Mandatory=$false, Position=5,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$false, Position=6,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2, 
    [Parameter(Mandatory=$false, Position=7,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3, 
    [Parameter(Mandatory=$false, Position=8,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4,
    [Parameter(Mandatory=$false, Position=9,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument5, 
    [Switch] $NoTest,
    [Switch] $NoTLS
)

. .\man.ps1

Function test-connection{
    <#
    This function test's if the pfsense is online by trying to connect to the webserver.
    it accept's the NoTLS switch parameter with you can use if the pfsense uses port 80.
    If the Reboot switch is given the function wait's till the pfsense is back online afther the reboot.
    #>
    Param
    (     
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Server')] [PSObject] $Server,
        [Switch] $reboot,
        [Switch] $NoTLS
    )
    if ($NoTLS){
        $port = '80'}
    else{
        $port = '443'}
    $online = Test-NetConnection -port $port $Server | Out-Null
    while (($reboot) -and ($online.TcpTestSucceeded -eq $false)){
        sleep -Seconds 5
        $online = Test-NetConnection -port $port $Server | Out-Null
    }
    if ((!$reboot) -and ($online.TcpTestSucceeded -eq $false)){
        exit
    }

}

Function Connect-pfSense{
    <#
    This Function connect's to the webinterface of the pfsense.
    With the NoTLS switch port 80 can be used instead of 443

    # ToDo Check is login

    #>
    Param
    (
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Server')][PSObject] $Server,
        [Parameter(Mandatory=$true, Position=1,HelpMessage='Credentials')][PSObject] $Credentials,
        [Switch] $NoTLS
    )
    $uri = 'https://{0}/index.php' -f $Server
    $pfWebSession = $null
    $retObject = @()
    $dictOptions = @{
         host=$Server
         NoTLS=$([bool] $NoTLS)
         }
    If ($NoTLS) 
        {
            $uri = $uri -Replace "^https:",'http:'
            Write-Warning -Message 'WARNING NO TLS SECURTIY!!! '
        }
    $request = Invoke-WebRequest -Uri $uri
    $webCredential = @{login='Login'
        usernamefld=$Credentials.GetNetworkCredential().UserName
        passwordfld=$Credentials.GetNetworkCredential().Password
        __csrf_magic=$($request.InputFields[0].Value)
    }
    $login = Invoke-WebRequest -Uri $uri -Body $webCredential -Method Post -SessionVariable pfWebSession | Out-Null
    return [pscustomobject] @{     
        'pfWebSession' = $pfWebSession
        'dictOptions' = $dictOptions
    }
}

Function Post-request{
    <#
    This Function does the actual upload to the website of the pfsense.
    it can do a normal upload our a multipart form (which is used for the backup and restore page)
    to use the multipart mode use the switch -Multiform
    #>
    Param
    (
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Session,
        [Parameter(Mandatory=$true, Position=1,HelpMessage='The PostData as a Dictonary')] [PSObject] $dictPostData,
        [Parameter(Mandatory=$true, Position=2,HelpMessage='The Uri Get extension to setup the connection')] [PSObject] $UriGetExtension, 
        [Parameter(Mandatory=$true, Position=3,HelpMessage='The Uri post extension for the post request')] [PSObject] $UriPostExtension,
        [Switch] $Multiform
    )
    [bool] $NoTLS = $Session.dictOptions.NoTLS
    [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session.pfWebSession
    $uri = 'https://{0}/{1}' -f $Server, $UriGetExtension
    If ($NoTLS) 
    {
        $uri = $uri -Replace "^https:",'http:'
        Write-Warning -Message 'WARNING NO TLS SECURTIY!!! '
    }
    $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
    $dictPostData.add("__csrf_magic","$($request.InputFields[0].Value)")
    $uri = $uri -replace $UriGetExtension,$UriPostExtension
    Try
    {
        if ($Multiform) {
            $boundry = "-----" + [System.Guid]::NewGuid().ToString()
            $LF = "`r`n" 
            $bodyLines = (
            "--$boundry",
            "Content-Disposition: form-data; name=`"__csrf_magic`"",
            '',
            $dictPostData.item("__csrf_magic"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"backuparea`"",
            '',
            $dictPostData.item("backuparea"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"nopackages`"",
            '',
            $dictPostData.item("nopackages"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"donotbackuprrd`"",
            '',
            $dictPostData.item("donotbackuprrd"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"encrypt_password`"",
            '',
            $dictPostData.item("encrypt_password"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"download`"",
            '',
            $dictPostData.item("download"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"restorearea`"",
            '',
            $dictPostData.item("restorearea"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"conffile`"; filename=`"$($dictPostData.item("Filename"))`"",
            "Content-Type: application/octet-stream",
            '',
            $dictPostData.item("conffile"),
            "--$boundry",
            "Content-Disposition: form-data; name=`"decrypt_password`"",
            '',
            $dictPostData.item("decrypt_password"),
            "--$boundry--",
            "Content-Disposition: form-data; name=`"restore`"",
            '',
            $dictPostData.item("restore"),
            "--$boundry--") 
            $bodyLines = $bodyLines -join $LF
            $rawRet = Invoke-WebRequest -Uri $uri -Method Post -Body $bodyLines -WebSession $webSession -EA Stop -ContentType "multipart/form-data; boundary=$boundry" 
        }
        Else{
            $rawRet = Invoke-WebRequest -Uri $uri -Method Post -Body $dictPostData -WebSession $webSession -EA Stop
        }
    }
    Catch
    {
        Write-Error -Message 'Something went wrong Posting the data'
    }
    # Todo:
    # If no error, there should not be a alert in powershell
    $error_statement = $rawRet.ParsedHtml.body.getElementsByClassName("alert alert-danger input-errors")
    $error_alert = $error_statement | %{$_.InnerText}
    if ($error_alert){Write-Warning $error_alert -WarningAction Inquire}
}

Function Get-Request{
    <#
    This Function does a get request on the pfsense.
    #>
    Param
    (
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Session,
        [Parameter(Mandatory=$true, Position=1,HelpMessage='The Uri Get extension')] [PSObject] $UriGetExtension 
    )
    [bool] $NoTLS = $Session.dictOptions.NoTLS
    [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session.pfWebSession
    $uri = 'https://{0}/{1}' -f $Server,$UriGetExtension
    If ($NoTLS) 
    {
        $uri = $uri -Replace "^https:",'http:'
        Write-Warning -Message 'WARNING NO TLS SECURTIY!!! '
    }
    $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
    return $request
}

Function Logout {
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject]$Connection)
    $dictPostData = @{logout=""}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "index.php" -UriPostExtension "index.php"
}

# pfsense_api -server '' -username '' -Password '' -service Route -action print                                                                                          
Function Printe_route{
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_routes = get-Request -Session @Connection -UriGetExtension "system_routes.php"
    $all_routes = $($get_all_routes.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit") | %{$_.InnerText}).split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1
    $all_routes = $all_routes -replace "-", "" -replace "/"," " -replace "  "," "
    $indexNumber = 0
    write-host "Know routes are:"
    $all_routes | %{"{0}" -f $all_routes[$indexnumber]; $indexNumber++ } 
}

# pfsense_api -server '' -username '' -Password '' -service Route -action Add 192.168.0.0 24 WAN_DHCP "Description this must be between quotation marks"
Function Add_route{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4
)
    $dictPostData = @{
        network=$Argument1
        network_subnet=$Argument2
        gateway=$Argument3
        descr=$Argument4
        save="Save"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_routes_edit.php" -UriPostExtension "system_routes_edit.php"
    $dictPostData = @{
        apply="Apply+Changes"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_routes.php" -UriPostExtension "system_routes.php"
}

#pfsense_api -server '' -username '' -Password '' -service Route -action Delete 192.168.0.0 24 WAN_DHCP 
Function delete_route{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3)
    $get_all_routes = get-Request -Session $Connection -UriGetExtension "system_routes.php"
    $route_to_delete = "{0}/{1} {2}" -f $Argument1,$Argument2,$Argument3
    $ID = $($($($get_all_routes.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit") | %{$_.innerHTML -split "<TR>"} | select-string -pattern $($($route_to_delete) -split("\s+"))[0]) -split "<A" | select-string -pattern 'title="Delete route"')  -split ";")[1] -replace "[^0-9]" , ''
    $dictPostData = @{
            act="del"
            id=$ID}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_routes_edit.php" -UriPostExtension "system_routes.php"
}

# pfsense_api -server '' -username '' -Password '' -service interface -action print
function print_interface{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection
    ) 
    $get_all_interfaces = get-Request -Session @Connection -UriGetExtension ""
    $all_interfaces = $($get_all_interfaces.ParsedHtml.getElementById("widget-interfaces-0").innerText).split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1 | Select -SkipLast 9
    $indexNumber = 0
    $all_interfaces | %{"{0}" -f $all_interfaces[$indexnumber]; $indexNumber++ }
}

# pfsense_api -server '' -username '' -Password '' -service gateway -action print
function print_Gateway{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection
    ) 
    $get_all_gateways = get-Request -Session @Connection -UriGetExtension "system_gateways.php"
    $all_gateways = $($get_all_gateways.ParsedHtml.getElementById("gateways").innerText).split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1
    $indexNumber = 0
    $all_gateways | %{"{0}" -f $all_gateways[$indexnumber]; $indexNumber++ }
}

# pfsense_api -server '' -username '' -Password '' -service Route -action Add Name 192.168.0.2 192.168.0.2 WAN "Description this must be between quotation marks"
function add_Gateway{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument5
    )
    # PFsense uses the network internal name's so we have to map those to the client names
    $get_all_netwoks = get-Request -Session @Connection -UriGetExtension "system_gateways_edit.php?id=0"
    $get_all_netwoks.ParsedHtml.getElementById("interface") | %{if ($_.textContent -eq "$Argument4"){$interface_intern = $_.value}}
    $dictPostData = @{
        interface=$interface_intern
        ipprotocol="inet"
        name=$Argument1
        gateway=$Argument2
        monitor=$Argument3
        descr=$Argument5
        weight="1"
        data_payload=""
        latencylow=""
        latencyhigh=""
        losslow=""
        losshigh=""
        interval=""
        loss_interval=""
        time_period=""
        alert_interval=""
        friendlyiface=""
        save="Save"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways_edit.php"
    $dictPostData = @{
        apply="Apply+Changes"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
}

# pfsense_api -server '' -username '' -Password '' -service Gateway -action delete new_gateway
Function delete_Gateway{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    $get_all_gateways = get-Request -Session $Connection -UriGetExtension "system_gateways.php"
    $ID = $($($get_all_gateways.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit") | %{$_.innerHTML -split "<TR"} | select-string -pattern $Argument1 | %{$_ -split "<TD"} | %{$_ -split "<A"} | select-string -pattern 'title="Delete gateway"') -split ";")[1] -replace "[^0-9]" , ''
    $dictPostData = @{
            act="del"
            id=$ID}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
    $dictPostData = @{
        apply="Apply+Changes"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
}

#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action print
Function print_dnsresolver{    
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection
    ) 
    $get_all_dnsresolver = get-Request -Session @Connection -UriGetExtension "services_unbound.php"
    $NetworkInterfaces = ""
    $($get_all_dnsresolver.ParsedHtml.getElementById("active_interface[]")) | %{if($_.selected) {$NetworkInterfaces += $_.text}}
    $OutgoingNetworkInterfaces = ""
    $($get_all_dnsresolver.ParsedHtml.getElementById("outgoing_interface[]")) | %{if($_.selected) {$OutgoingNetworkInterfaces += $_.text}}
    $Customoptions = ""
    $Customoptions += $($get_all_dnsresolver.ParsedHtml.getElementById("custom_options")).value

    $HostOverrides = ""
    $HostOverrides += $($($($($get_all_dnsresolver.ParsedHtml.body.getElementsByClassName("container static") | %{$_.InnerText}) -split("`n`r")) | Select-String -Pattern 'Host Overrides') -split ("hostDescriptionActions"))[1]
    $DomainOverrides = ""
    $DomainOverrides += $($($($($get_all_dnsresolver.ParsedHtml.body.getElementsByClassName("container static") | %{$_.InnerText}) -split("`n`r")) | Select-String -Pattern 'Domain Overrides') -split ("AddressDescriptionActions"))[1]

    "Selected network interface are:`n`r{0}`n`r`n`rSelected outgoing interfaces are:`n`r{1}`n`r`n`rCostum options are:`n`r{2}`n`r`n`rHost override's are:{3}`n`r`n`rDomain override's are:{4}" -f $NetworkInterfaces,$OutgoingNetworkInterfaces,$Customoptions,$HostOverrides,$DomainOverrides
}

#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action UploadCustom "Custom File" 
Function UploadCustom_dnsresolver{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1
    )
    # ToDo: check if file in same location or if full path is given
    $CostumOptions = $(get-Content $Argument1) -join "`n`r"
    $get_all_unbound = get-Request -Session @Connection -UriGetExtension "services_unbound.php"
    $dictPostData = @{
        "enable" = $($get_all_unbound.ParsedHtml.getElementById("enable")).value
        "port" = $($get_all_unbound.ParsedHtml.getElementById("port")).value
        "enablessl" = $($get_all_unbound.ParsedHtml.getElementById("enablessl")).value
        "sslport" = $($get_all_unbound.ParsedHtml.getElementById("sslport")).value
        "dnssec" = $($get_all_unbound.ParsedHtml.getElementById("dnssec")).value
        "custom_options" = $CostumOptions
        "save"="save"
    }
    $($get_all_unbound.ParsedHtml.getElementById("sslcertref")) | %{if($_.selected) {$dictPostData.Add("sslcertref",$_.value())}}
    $($get_all_unbound.ParsedHtml.getElementById("active_interface[]")) | %{if($_.selected) {$dictPostData.Add("active_interface[]",$_.value())}}
    $($get_all_unbound.ParsedHtml.getElementById("outgoing_interface[]")) | %{if($_.selected) {$dictPostData.Add("outgoing_interface[]",$_.value())}}
    $($get_all_unbound.ParsedHtml.getElementById("system_domain_local_zone_type")) | %{if($_.selected) {$dictPostData.Add("system_domain_local_zone_type",$_.value())}}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}

#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action addhost host domain ipaddress "Description this must be between quotation marks"
Function addhost_dnsresolver{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4
    )
    $dictPostData = @{
        host=$Argument1
        domain=$Argument2
        ip=$Argument3
        descr=$Argument4
        aliashost0=""
        aliasdomain0=""
        aliasdescription0=""
        save="Save"
    }
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound_host_edit.php" -UriPostExtension "services_unbound_host_edit.php"
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}

Function Deletehost_dnsresolver{
    Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2)
    $get_all_resolverhosts = get-Request -Session $Connection -UriGetExtension "services_unbound.php"
    $ID = $($($($($($get_all_resolverhosts.ParsedHtml.body.getElementsByClassName("container static") | %{$_.outerHTML}) -split("<TR")) | Select-String -Pattern "<TD>$Argument1" | Select-String -Pattern "<TD>$Argument2") -split ("<A") | Select-String -Pattern "Edit host override") -split "id=")[1] -replace "[^0-9]" , ''
    $dictPostData = @{
            type="host"
            act="del"
            id=$ID}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}


$DefaulkCred  = New-Object System.Management.Automation.PSCredential ($Username, $(ConvertTo-SecureString -string $password -AsPlainText -Force))
if (-not $service -or $service -eq "Help" -or $service -eq "H"){$HelpMessageheader
    $manall
    exit}
elseif ( -not $NoTest -AND -not $NoTLS){test-connection -Server $Server ; $Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred} # has test and tls
elseif ( -not $Notest){test-connection -Server $Server -NoTLS ;$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS} #has test and no tls
elseif ( -not $NoTLS){$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred} #has no test and tls
else{$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS} # has test and no tls 

try {
    $connected = get-Request -Session @Connection -UriGetExtension ""
    if ($connected.ParsedHtml.getElementById("login")){write-error "Please enter the correct credentials" ; exit}
}catch{}

if ($service -eq "route"){
    if (-not $Action -or $action -eq "Help" -or $Action -eq "H"){$manroute}
    elseif ($action -eq "print"){Printe_route -Connection @Connection}
    elseif ($action -eq "add"){add_route -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4}
    elseif ($action -eq "delete"){delete_route -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3}  
}

elseif ($service -eq "Interface"){
    if (-not $Action -or $action -eq "Help" -or $Action -eq "H"){$manint}
    elseif ($action -eq "print"){print_interface -Connection @Connection}
}

elseif ($service -eq "Gateway"){
    if (-not $Action -or $action -eq "Help" -or $Action -eq "H"){$manGateway}
    elseif ($action -eq "print"){print_Gateway -Connection @Connection}
    elseif ($action -eq "add"){add_Gateway -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4 -argument5 $Argument5}
    elseif ($action -eq "delete"){delete_Gateway -Connection @Connection -Argument1 $Argument1}  

}

elseif ($service -eq "dnsresolver"){
    if (-not $Action -or $action -eq "Help" -or $Action -eq "H"){$mandnsresolver}
    elseif ($action -eq "print"){print_dnsresolver -Connection @Connection}
    elseif ($action -eq "UploadCustom"){UploadCustom_dnsresolver -Connection @Connection -Argument1 $Argument1 }
    elseif ($action -eq "addhost"){addhost_dnsresolver -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -Argument4 $Argument4}
    elseif ($action -eq "Deletehost"){Deletehost_dnsresolver -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2}

}

if ($Connection){Logout -Connection @Connection}

