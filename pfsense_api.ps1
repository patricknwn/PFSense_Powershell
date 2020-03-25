Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='The Server address')] [PSObject] $Server,
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Username')] [PSObject] $Username,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Password')] [PSObject] $Password,
    [Parameter(Mandatory=$false, Position=3,HelpMessage='The service you would like to talke to')] [PSObject] $service,
    [Parameter(Mandatory=$false, Position=4,HelpMessage='The action you would like to do on the service')] [PSObject] $Action,
    [Parameter(Mandatory=$false, Position=5,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1 = " ",
    [Parameter(Mandatory=$false, Position=6,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2 = " ", 
    [Parameter(Mandatory=$false, Position=7,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3 = " ", 
    [Parameter(Mandatory=$false, Position=8,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4 = " ",
    [Parameter(Mandatory=$false, Position=9,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument5 = " ", 
    [Parameter(Mandatory=$false, Position=10,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument6 = " ", 
    [Parameter(Mandatory=$false, Position=11,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument7 = " ", 

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
    Param(     
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Server')] [PSObject] $Server,
        [Switch] $reboot,
        [Switch] $NoTLS)
    if ($NoTLS){
        $port = '80'}
    else{
        $port = '443'}
    $online = Test-NetConnection -port $port $Server 
    while (($reboot) -and ($online.TcpTestSucceeded -eq $false)){
        sleep -Seconds 5
        $online = Test-NetConnection -port $port $Server
    }
    if ((!$reboot) -and ($online.TcpTestSucceeded -eq $false)){
        "Could not connect to port: {0}, the ping request was: {1} " -f $online.RemotePort,$online.PingSucceeded
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
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,
        [Parameter(Mandatory=$true, Position=1,HelpMessage='The PostData as a Dictonary')] [PSObject] $dictPostData,
        [Parameter(Mandatory=$true, Position=2,HelpMessage='The Uri Get extension to setup the connection')] [PSObject] $UriGetExtension, 
        [Parameter(Mandatory=$true, Position=3,HelpMessage='The Uri post extension for the post request')] [PSObject] $UriPostExtension,
        [Switch] $Multiform
    )
    [bool] $NoTLS = $Connection.dictOptions.NoTLS
    [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Connection.pfWebSession
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
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,
        [Parameter(Mandatory=$true, Position=1,HelpMessage='The Uri Get extension')] [PSObject] $UriGetExtension 
    )
    [bool] $NoTLS = $Connection.dictOptions.NoTLS
    [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Connection.pfWebSession
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
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "index.php" -UriPostExtension "index.php"
}


Function Printe_route{
# pfsense_api -server '' -username '' -Password '' -service Route -action print                                                                                          
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_routes = get-Request -Connection @Connection -UriGetExtension "system_routes.php"
    $all_routes = $($get_all_routes.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit") | %{$_.InnerText}).split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1
    $all_routes = @($all_routes -replace "-", "" -replace "/"," " -replace "  "," ")
    $indexNumber = 0
    write-host "Know routes are:"
    $all_routes | %{"{0}" -f $all_routes[$indexnumber]; $indexNumber++ } 
}


Function Add_route{
# pfsense_api -server '' -username '' -Password '' -service Route -action Add 192.168.0.0 24 WAN_DHCP "Description this must be between quotation marks"
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4)
    $dictPostData = @{
        network=$Argument1
        network_subnet=$Argument2
        gateway=$Argument3
        descr=$Argument4
        save="Save"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_routes_edit.php" -UriPostExtension "system_routes_edit.php"
    $dictPostData = @{
        apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_routes.php" -UriPostExtension "system_routes.php"
}


Function delete_route{
#pfsense_api -server '' -username '' -Password '' -service Route -action Delete 192.168.0.0 24 WAN_DHCP 
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3)
    $get_all_routes = get-Request -Connection $Connection -UriGetExtension "system_routes.php"
    $route_to_delete = "{0}/{1} {2}" -f $Argument1,$Argument2,$Argument3
    try{
    $ID = $($($($get_all_routes.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit") | %{$_.innerHTML -split "<TR>"} | select-string -pattern $($($route_to_delete) -split("\s+"))[0]) -split "<A" | select-string -pattern 'title="Delete route"')  -split ";")[1] -replace "[^0-9]" , ''
    }catch{write-warning "Did not find the combination you entered"}
    $ID = $ID -join ""
    $dictPostData = @{
            act="del"
            id=$ID}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_routes_edit.php" -UriPostExtension "system_routes.php"
}


function print_interface{
# pfsense_api -server '' -username '' -Password '' -service interface -action print
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_interfaces = get-Request -Connection @Connection -UriGetExtension ""
    $all_interfaces = @($($get_all_interfaces.ParsedHtml.getElementById("widget-interfaces-0").innerText).split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1 | Select -SkipLast 9)
    $indexNumber = 0
    $all_interfaces | %{"{0}" -f $all_interfaces[$indexnumber]; $indexNumber++ }
}


function print_Gateway{
# pfsense_api -server '' -username '' -Password '' -service gateway -action print
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_gateways = get-Request -Connection @Connection -UriGetExtension "system_gateways.php"
    $all_gateways = @($($get_all_gateways.ParsedHtml.getElementById("gateways").innerText).split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1)
    $indexNumber = 0
    $all_gateways | %{"{0}" -f $all_gateways[$indexnumber]; $indexNumber++ }
}


function add_Gateway{
# pfsense_api -server '' -username '' -Password '' -service Route -action Add Name 192.168.0.2 192.168.0.2 WAN "Description this must be between quotation marks"
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument5
    )
    # PFsense uses the network internal name's so we have to map those to the client names
    $get_all_netwoks = get-Request -Connection @Connection -UriGetExtension "system_gateways_edit.php?id=0"
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
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways_edit.php"
    $dictPostData = @{
        apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
}


Function delete_Gateway{
# pfsense_api -server '' -username '' -Password '' -service Gateway -action delete new_gateway
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    $get_all_gateways = get-Request -Connection $Connection -UriGetExtension "system_gateways.php"
    try{
    $ID = $($($get_all_gateways.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit") | %{$_.innerHTML -split "<TR"} | select-string -pattern $Argument1 | %{$_ -split "<TD"} | %{$_ -split "<A"} | select-string -pattern 'title="Delete gateway"') -split ";")[1] -replace "[^0-9]" , ''
    }catch{write-warning "Did not find the combination you entered"}
    $ID = $ID -join ""
    $dictPostData = @{
            act="del"
            id=$ID}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
    $dictPostData = @{
        apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
}


Function default_Gateway{
#pfsense_api -server '' -username '' -Password '' -service Gateway -action default new_gateway"
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    $get_all_gateways = get-Request -Connection $Connection -UriGetExtension "system_gateways.php"
    if ($($get_all_gateways.ParsedHtml.getElementById("defaultgw4") | %{$_.textContent}) -notcontains $Argument1){"The Gateway you entered: {0} coud not be found" -f $Argument1 ; exit}
    $get_all_gateways.ParsedHtml.getElementById("defaultgw4") | %{if ($_.textContent -eq $Argument1){$defaultgw4 = $_.value}}
    $dictPostData = @{
    defaultgw4=$defaultgw4
    defaultgw6="" 
    save="Save"
    }
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "system_gateways.php" -UriPostExtension "system_gateways.php"
}


Function print_dnsresolver{    
#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action print
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_dnsresolver = get-Request -Connection @Connection -UriGetExtension "services_unbound.php"
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


Function UploadCustom_dnsresolver{
#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action UploadCustom "Custom File" 
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    # ToDo: check if file in same location or if full path is given
    $CostumOptions = $(get-Content $Argument1) -join "`n`r"
    $get_all_unbound = get-Request -Connection  @Connection -UriGetExtension "services_unbound.php"
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
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}


Function addhost_dnsresolver{
#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action addhost host domain ipaddress "Description this must be between quotation marks"
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4)
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
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound_host_edit.php" -UriPostExtension "services_unbound_host_edit.php"
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}


Function Deletehost_dnsresolver{
#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action deletehost host domain
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2)
    $get_all_resolverhosts = get-Request -Connection $Connection -UriGetExtension "services_unbound.php"
    try{
    $ID = $($($($($($($get_all_resolverhosts.ParsedHtml.body.getElementsByClassName("container static") | %{$_.outerHTML}) -split("<TR")) | Select-String -Pattern "<TD>$Argument1" | Select-String -Pattern "<TD>$Argument2") -split ("<A") | Select-String -Pattern "Edit host override") -split "id=")[1]) -split(";")[0] -replace "[^0-9]" , ''
    }catch{write-warning "Did not find the combination you entered"}
    $ID = $ID -join ""
    $dictPostData = @{
            type="host"
            act="del"
            id=$ID}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}


Function adddomain_dnsresolver{
#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action adddomain domain ipaddress "Description this must be between quotation marks"
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3)
    $dictPostData = @{
        domain=$Argument1
        ip=$Argument2
        tls_hostname=""
        descr=$Argument3
        save="Save"
    }
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound_domainoverride_edit.php" -UriPostExtension "services_unbound_domainoverride_edit.php"
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}


Function Deletedomain_dnsresolver{
#pfsense_api -server '' -username '' -Password '' -service dnsresolver -action deletedomain domain
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    $get_all_resolverdomains = get-Request -Connection $Connection -UriGetExtension "services_unbound.php"
    try{
    $ID = $($($($($($($get_all_resolverdomains.ParsedHtml.body.getElementsByClassName("container static") | %{$_.outerHTML}) -split("<TR")) | Select-String -Pattern "<TD>$Argument1") -split ("<A") | Select-String -Pattern "Domain Override") -split "id=")[1]) -split(";")-replace "[^0-9]" , ''
    }catch{write-warning "Did not find the combination you entered"}
    $ID = $ID -join ""
    $dictPostData = @{
            type="doverride"
            act="del"
            id=$ID}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}


Function print_portfwd{
#pfsense_api -server '' -username '' -Password '' -service portfwd -action print
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_Portfwd = get-Request -Connection @Connection -UriGetExtension "firewall_nat.php"
    $all_portfwd = @($($get_all_Portfwd.ParsedHtml.getElementById("ruletable") | %{$_.InnerText}) -split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1)
    $indexNumber = 0
    $all_portfwd | %{"{0}" -f $all_portfwd[$indexnumber]; $indexNumber++ }
}


Function add_portfwd{
#pfsense_api -server '' -username '' -Password '' -service portfwd -action add Interface Protocol Dest_Address Dest_Ports NAT_IP NAT_Ports `"Description this must be between quotation marks`""
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4,
    [Parameter(Mandatory=$true, Position=5,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument5,
    [Parameter(Mandatory=$true, Position=6,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument6,
    [Parameter(Mandatory=$true, Position=7,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument7)
    $get_all_netwoks = get-Request -Connection @Connection -UriGetExtension "system_gateways_edit.php?id=0"
    $get_all_netwoks.ParsedHtml.getElementById("interface") | %{if ($_.textContent -eq "$Argument1"){$interface_intern = $_.value}}
    $dictPostData = @{
        interface=$interface_intern
        proto=$Argument2
        srctype="any"
        srcbeginport="any"
        srcendport="any"
        dsttype="single"
        dst=$Argument3
        dstbeginport=""
        dstbeginport_cust=$Argument4
        dstendport=""
        dstendport_cust=""
        localip=$Argument5
        localbeginport=""
        localbeginport_cust=$Argument6
        descr=$Argument7
        natreflection="default"
        "filter-rule-association"=""
        after=""
        save="Save"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_nat_edit.php" -UriPostExtension "firewall_nat_edit.php"
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_nat.php" -UriPostExtension "firewall_nat.php"

}


Function Delete_portfwd{
#pfsense_api -server '' -username '' -Password '' -service portfwd -action delete Dest_Address Dest_Ports NAT_IP NAT_Ports
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4)
    $get_all_Portfwd = get-Request -Connection @Connection -UriGetExtension "firewall_nat.php"
    try{
    $ID = $($($($($($get_all_Portfwd.ParsedHtml.getElementById("ruletable")| %{$_.outerHTML}) -split("<TR") | Select-String -Pattern "<TD>$Argument1" | Select-String -Pattern "<TD>$Argument2" | Select-String -Pattern "<TD>$Argument3" | Select-String -Pattern "<TD>$Argument4" ) -split ("<A") | Select-String -Pattern "firewall_nat_edit") -split "id=")[1]) -split (";") -replace "[^0-9]" , ''
    }catch{write-warning "Did not find the combination you entered"}
    $ID = $ID -join ""
    $dictPostData = @{
        act="del"
        id=$ID}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_nat.php" -UriPostExtension "firewall_nat.php"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_nat.php" -UriPostExtension "firewall_nat.php"
}


Function print_Alias{
#pfsense_api -server '' -username '' -Password '' -service Alias -action print
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_IPAlias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases.php?tab=ip"
    $all_IPAlias = $(@($($get_all_IPAlias.ParsedHtml.body.getElementsByClassName("table-responsive") | %{$_.InnerText}) -split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1)) -join "`n`r"
    $get_all_PortAlias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases.php?tab=port"
    $all_PortAlias = $(@($($get_all_PortAlias.ParsedHtml.body.getElementsByClassName("table-responsive") | %{$_.InnerText}) -split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1)) -join "`n`r"
    $get_all_URLAlias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases.php?tab=url"
    $all_URLAlias = $(@($($get_all_URLAlias.ParsedHtml.body.getElementsByClassName("table-responsive") | %{$_.InnerText}) -split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1)) -join "`n`r"
    "Firewall Aliases IP:`n`r{0}`n`r`n`nFirewall Aliases Ports:`n`r{1}`n`r`n`rFirewall Aliases URLs`n`r{2}" -f $all_IPAlias,$all_PortAlias,$all_URLAlias
}


Function SpecificPrint_Alias{
#pfsense_api -server '' -username '' -Password '' -service Alias -action SpecificPrint name
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection,
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    $get_all_alias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases.php?tab=all"
    try{$ID = $($($($($($($get_all_alias.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed sortable-theme-bootstrap")| %{$_.outerHTML}) -split("<TR") | Select-String -Pattern $Argument1) -split("<TD"))[1]) -split "id=")[1] -split(";"))[0] -replace "[^0-9]" , ''}
    catch{write-warning "Did not find the Alias you entered"}
    $ID = $ID -join ""
    $get_alias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases_edit.php?id=$ID"
    $indexNumber = 0
    $($get_alias.ParsedHtml.getElementById("type")) | %{if($_.selected) {$type_value = $_.value()} }
    if($type_value -eq "network"){
        while($True){
            if(-not $($get_alias.ParsedHtml.getElementById("address$indexnumber")).value){break}
            "{0} {1} {2}" -f $($get_alias.ParsedHtml.getElementById("address$indexnumber").value),$($get_alias.ParsedHtml.getElementById("address_subnet$indexnumber").value),$($get_alias.ParsedHtml.getElementById("detail$indexnumber").value)
            $indexNumber++}}
    else{
        while($True){
            if(-not $($get_alias.ParsedHtml.getElementById("address$indexnumber")).value){break}
            "{0} {1}" -f $($get_alias.ParsedHtml.getElementById("address$indexnumber").value),$($get_alias.ParsedHtml.getElementById("detail$indexnumber").value)
            $indexNumber++}}
}


Function add_Alias{
#pfsense_api -server '' -username '' -Password '' -service Alias -action add Type Name `"Description this must be between quotation marks`" Address Subnet(CIDR method)
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4,
    [Parameter(Mandatory=$false, Position=5,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument5)
    if($Argument1 -eq "Host"){$dictPostData = @{
        name=$Argument2
        descr=$Argument3
        type="host"
        address0=$Argument4
        detail0="First Value"
        tab="ip"
        origname=""
        save="Save"}
        Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?tab=ip" -UriPostExtension "firewall_aliases_edit.php?tab=ip"}
    if($Argument1 -eq "Port"){$dictPostData = @{
        name=$Argument2
        descr=$Argument3
        type="Port"
        address0=$Argument4
        detail0="First Value"
        tab="port"
        origname=""
        save="Save"}
        Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?tab=port.php" -UriPostExtension "firewall_aliases_edit.php?tab=port.php"}
    if($Argument1 -eq "network"){$dictPostData = @{
        name=$Argument2
        descr=$Argument3
        type="network"
        address0=$Argument4
        address_subnet0=$Argument5
        detail0="First Value"
        tab="ip"
        origname=""
        save="Save"}
        Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?tab=ip.php" -UriPostExtension "firewall_aliases_edit.php?tab=ip.php"}
    if($Argument1 -eq "url"){$dictPostData = @{
        name=$Argument2
        descr=$Argument3
        type="url"
        address0=$Argument4
        address_subnet0=$Argument5
        detail0="First Value"
        tab="url"
        origname=""
        save="Save"}
        Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?tab=url.php" -UriPostExtension "firewall_aliases_edit.php?tab=url.php"}
    $dictPostData = @{"apply"="Apply Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases.php?tab=all" -UriPostExtension "firewall_aliases.php?tab=all"
}


Function delete_Alias{
#pfsense_api -server '' -username '' -Password '' -service Alias -action delete name
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection,
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    $get_all_alias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases.php?tab=all"
    try{$ID = $($($($($($($get_all_alias.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed sortable-theme-bootstrap")| %{$_.outerHTML}) -split("<TR") | Select-String -Pattern $Argument1) -split("<TD"))[1]) -split "id=")[1] -split(";"))[0] -replace "[^0-9]" , ''}
    catch{write-warning "Did not find the Alias you entered"}
    $ID = $ID -join ""
    $dictPostData = @{
        act="del"
        tab="all"
        id=$ID}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php" -UriPostExtension "firewall_aliases.php?tab=all"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php" -UriPostExtension "firewall_aliases.php?tab=all"
}


Function addvalue_Alias{
#pfsense_api -server '' -username '' -Password '' -service Alias -action addvalue name `"Description this must be between quotation marks`" Address Subnet(CIDR method) 'Subnet is only necessary if you add to a network alias'
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$False, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4)
    $get_all_alias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases.php?tab=all"
    try{$ID = $($($($($($($get_all_alias.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed sortable-theme-bootstrap")| %{$_.outerHTML}) -split("<TR") | Select-String -Pattern $Argument1) -split("<TD"))[1]) -split "id=")[1] -split(";"))[0] -replace "[^0-9]" , ''}
    catch{write-warning "Did not find the Alias you entered"}
    $ID = $ID -join ""
    $get_alias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases_edit.php?id=$ID"
    $($get_alias.ParsedHtml.getElementById("type")) | %{if($_.selected) {$type_value = $_.value()} }
    $dictPostData = @{
        name=$($get_alias.ParsedHtml.getElementById("name").value)
        descr=$($get_alias.ParsedHtml.getElementById("descr").value)
        tab=$($get_alias.ParsedHtml.getElementById("tab").value)
        type=$type_value
        origname=$($get_alias.ParsedHtml.getElementById("origname").value)
        id=$($get_alias.ParsedHtml.getElementById("id").value)
        save="Save"}
    $indexNumber = 0
    $($get_alias.ParsedHtml.getElementById("type")) | %{if($_.selected) {$type_value = $_.value()} }
    if($type_value -eq "network"){
        while($True){
            if(-not $($get_alias.ParsedHtml.getElementById("address$indexnumber")).value){break}
            $dictPostData.Add("address$indexnumber",$($get_alias.ParsedHtml.getElementById("address$indexnumber").value))
            $dictPostData.Add("address_subnet$indexnumber",$($get_alias.ParsedHtml.getElementById("address_subnet$indexnumber").value))
            $dictPostData.Add("detail$indexnumber",$($get_alias.ParsedHtml.getElementById("detail$indexnumber").value))
            $indexNumber++}
        $dictPostData.Add("address$indexnumber",$Argument3)
        $dictPostData.Add("address_subnet$indexnumber",$Argument4)
        $dictPostData.Add("detail$indexnumber",$Argument2)
        }
    else{
        while($True){
            if(-not $($get_alias.ParsedHtml.getElementById("address$indexnumber")).value){break}
            $dictPostData.Add("address$indexnumber",$($get_alias.ParsedHtml.getElementById("address$indexnumber").value))
            $dictPostData.Add("detail$indexnumber",$($get_alias.ParsedHtml.getElementById("detail$indexnumber").value))
            $indexNumber++}
        $dictPostData.Add("address$indexnumber",$Argument3)
        $dictPostData.Add("detail$indexnumber",$Argument2)
        }
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?id=$ID" -UriPostExtension "firewall_aliases_edit.php?id=$ID"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php" -UriPostExtension "firewall_aliases.php?tab=all"
}


Function deletevalue_Alias{
#pfsense_api -server '' -username '' -Password '' -service Alias -action deletevalue name Value Subnet(CIDR method) 'Subnet is only necessary if you add to a network alias'
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$False, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4)
    $get_all_alias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases.php?tab=all"
    try{$ID = $($($($($($($get_all_alias.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed sortable-theme-bootstrap")| %{$_.outerHTML}) -split("<TR") | Select-String -Pattern $Argument1) -split("<TD"))[1]) -split "id=")[1] -split(";"))[0] -replace "[^0-9]" , ''}
    catch{write-warning "Did not find the Alias you entered"}
    $ID = $ID -join ""
    $get_alias = get-Request -Connection @Connection -UriGetExtension "firewall_aliases_edit.php?id=$ID"
    $($get_alias.ParsedHtml.getElementById("type")) | %{if($_.selected) {$type_value = $_.value()} }
    $dictPostData = @{
        name=$($get_alias.ParsedHtml.getElementById("name").value)
        descr=$($get_alias.ParsedHtml.getElementById("descr").value)
        tab=$($get_alias.ParsedHtml.getElementById("tab").value)
        type=$type_value
        origname=$($get_alias.ParsedHtml.getElementById("origname").value)
        id=$($get_alias.ParsedHtml.getElementById("id").value)
        save="Save"}
    $indexNumber = 0
    if($type_value -eq "network"){
        while($True){
            if(-not $($get_alias.ParsedHtml.getElementById("address$indexnumber")).value){break}
            if(($get_alias.ParsedHtml.getElementById("address$indexnumber").value -ne $Argument2) -or ($get_alias.ParsedHtml.getElementById("address_subnet$indexnumber").value -ne $Argument3)){
                $dictPostData.Add("address$indexnumber",$($get_alias.ParsedHtml.getElementById("address$indexnumber").value))
                $dictPostData.Add("address_subnet$indexnumber",$($get_alias.ParsedHtml.getElementById("address_subnet$indexnumber").value))
                $dictPostData.Add("detail$indexnumber",$($get_alias.ParsedHtml.getElementById("detail$indexnumber").value))}
            $indexNumber++}
        }
    else{
        while($True){
            if(-not $($get_alias.ParsedHtml.getElementById("address$indexnumber")).value){break}
            if($get_alias.ParsedHtml.getElementById("address$indexnumber").value -ne $Argument2){
                $dictPostData.Add("address$indexnumber",$($get_alias.ParsedHtml.getElementById("address$indexnumber").value))
                $dictPostData.Add("detail$indexnumber",$($get_alias.ParsedHtml.getElementById("detail$indexnumber").value))}
            $indexNumber++}
        }
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?id=$ID" -UriPostExtension "firewall_aliases_edit.php?id=$ID"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php" -UriPostExtension "firewall_aliases.php?tab=all"
}


Function print_Vip{
#pfsense_api -server '' -username '' -Password '' -service Vip -action print
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $get_all_Vip = get-Request -Connection @Connection -UriGetExtension "firewall_virtual_ip.php"
    $all_Vip = $($get_all_Vip.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit sortable-theme-bootstrap") | %{$_.InnerText}).split([Environment]::NewLine) | Where-Object {$_} | Select -Skip 1                                                                    
    $all_Vip = @($all_Vip -replace "-", "" -replace "/"," " -replace "  "," ")
    $indexNumber = 0
    write-host "VIPs are:"
    $all_Vip | %{"{0}" -f $all_Vip[$indexnumber]; $indexNumber++ } 
}


Function add_Vip{
#pfsense_api -server '' -username '' -Password '' -service VIP -action add interface Address Subnet(CIDR method) `"Description this must be between quotation marks`" 
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument3,
    [Parameter(Mandatory=$true, Position=4,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument4)
    $get_all_Vip = get-Request -Connection @Connection -UriGetExtension "firewall_virtual_ip_edit.php"
    $get_all_Vip.ParsedHtml.getElementById("interface") | %{if ($_.textContent -eq "$Argument1"){$interface_intern = $_.value}}
    if( -not $interface_intern) {"Could not find the interface {0}" -f $Argument1 ; exit}
    $dictPostData = @{
        mode="ipalias"
        interface=$interface_intern
        subnet=$Argument2
        subnet_bits=$Argument3
        descr=$Argument4
        uniqid=$get_all_Vip.ParsedHtml.getElementById("uniqid").value
        save="Save"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_virtual_ip_edit.php" -UriPostExtension "firewall_virtual_ip_edit.php"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_virtual_ip_edit.php" -UriPostExtension "firewall_virtual_ip_edit.php"
}


Function delete_Vip{
#pfsense_api -server '' -username '' -Password '' -service Delete -action delete Ip_address
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection,
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1)
    $get_all_Vip = get-Request -Connection @Connection -UriGetExtension "firewall_virtual_ip.php"
    try{$ID = $($($($($($get_all_Vip.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed table-rowdblclickedit sortable-theme-bootstrap")| %{$_.outerHTML}) -split("<TR") | Select-String -Pattern $Argument1) -split("<TD") | Select-String -Pattern "firewall_virtual_ip_edit") -split "><A")[1]  -split "id=")[1] -replace "[^0-9]" , ''}
    catch{write-warning "Did not find the VIP you entered"}
    $ID = $ID -join ""
    $dictPostData = @{
        act="del"
        id=$ID}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_virtual_ip_edit.php" -UriPostExtension "firewall_virtual_ip.php"
    $dictPostData = @{apply="Apply+Changes"}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "firewall_virtual_ip_edit.php" -UriPostExtension "firewall_virtual_ip.php"
}


$DefaulkCred  = New-Object System.Management.Automation.PSCredential ($Username, $(ConvertTo-SecureString -string $password -AsPlainText -Force))
if (-not $service -or $service -eq "Help" -or $service -eq "H"){$HelpMessageheader
    $manall
    exit}
elseif (-not $action -or $action -eq "Help" -or $action -eq "H"){
    if($service -eq "route"){$manroute ; exit}
    elseif($service -eq "Interface"){$manint ; exit}
    elseif($service -eq "Gateway"){$manGateway ; exit}
    elseif($service -eq "dnsresolver"){$mandnsresolver ; exit}
    elseif($service -eq "portfwd"){$manportfwd ; exit}
    elseif($service -eq "Alias"){$ManAlias ; exit}
    elseif($service -eq "VIP"){$ManVIP ; exit}

    }
elseif ( -not $NoTest -AND -not $NoTLS){test-connection -Server $Server ; $Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred} # has test and tls
elseif ( -not $Notest){test-connection -Server $Server -NoTLS ; $Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS} #has test and no tls
elseif ( -not $NoTLS){$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred} #has no test and tls
else{$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS} # has test and no tls 

try {
    $connected = get-Request -Connection @Connection -UriGetExtension ""
    if ($connected.ParsedHtml.getElementById("login")){write-error "Please enter the correct credentials" ; exit}
}catch{}

if ($service -eq "route"){
    if ($action -eq "print"){Printe_route -Connection @Connection}
    elseif ($action -eq "add"){add_route -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4}
    elseif ($action -eq "delete"){delete_route -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3}  
}

elseif ($service -eq "Interface"){
    if ($action -eq "print"){print_interface -Connection @Connection}
}

elseif ($service -eq "Gateway"){
    if ($action -eq "print"){print_Gateway -Connection @Connection}
    elseif ($action -eq "add"){add_Gateway -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4 -argument5 $Argument5}
    elseif ($action -eq "delete"){delete_Gateway -Connection @Connection -Argument1 $Argument1}
    elseif ($action -eq "default"){default_Gateway -Connection @Connection -Argument1 $Argument1}

}

elseif ($service -eq "dnsresolver"){
    if ($action -eq "print"){print_dnsresolver -Connection @Connection}
    elseif ($action -eq "UploadCustom"){UploadCustom_dnsresolver -Connection @Connection -Argument1 $Argument1 }
    elseif ($action -eq "addhost"){addhost_dnsresolver -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -Argument4 $Argument4}
    elseif ($action -eq "Deletehost"){Deletehost_dnsresolver -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2}
    elseif ($action -eq "adddomain"){adddomain_dnsresolver -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3}
    elseif ($action -eq "deletedomain"){deletedomain_dnsresolver -Connection @Connection -Argument1 $Argument1}
}

elseif ($service -eq "portfwd"){
    if ($action -eq "print"){print_portfwd -Connection @Connection}
    elseif ($action -eq "Add"){add_portfwd -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4 -argument5 $Argument5 -Argument6 $Argument6 -Argument7 $Argument7}
    elseif ($action -eq "Delete"){Delete_portfwd -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4}
}

elseif ($service -eq "Alias"){
    if ($action -eq "print"){print_Alias -Connection @Connection}
    elseif ($action -eq "PrintSpecific"){SpecificPrint_Alias -Connection @Connection -Argument1 $Argument1}
    elseif ($action -eq "add"){add_Alias -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4 -argument5 $Argument5}
    elseif ($action -eq "delete"){delete_Alias -Connection @Connection -Argument1 $Argument1}
    elseif ($action -eq "addvalue"){addvalue_Alias -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4}
    elseif ($action -eq "deletevalue"){deletevalue_Alias -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3}
}

elseif ($service -eq "Vip"){
    if ($action -eq "print"){print_Vip -Connection @Connection}
    elseif ($Action -eq "add"){add_Vip -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4}
    elseif ($Action -eq "delete"){delete_Vip -Connection @Connection -Argument1 $Argument1}

}

if ($Connection){Logout -Connection @Connection}

# $server = "192.168.0.1" ; $Username = "admin" ; $password = "pfsense"