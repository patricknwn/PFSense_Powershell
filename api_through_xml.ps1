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
    [Parameter(Mandatory=$false, Position=12,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument8 = " ", 
    [Parameter(Mandatory=$false, Position=13,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument9 = " ", 
    [Parameter(Mandatory=$false, Position=14,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument10 = " ", 
    [Parameter(Mandatory=$false, Position=15,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument11 = " ", 
    [Parameter(Mandatory=$false, Position=16,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument12 = " ", 
    [Parameter(Mandatory=$false, Position=17,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument13 = " ",
    [Parameter(Mandatory=$false, Position=18,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument14 = " ",  
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
            Write-debug -Message 'WARNING NO TLS SECURTIY!!! '
        }
    $request = Invoke-WebRequest -UseBasicParsing -Uri $uri
    $webCredential = @{login='Login'
        usernamefld=$Credentials.GetNetworkCredential().UserName
        passwordfld=$Credentials.GetNetworkCredential().Password
        __csrf_magic=$($request.InputFields[0].Value)
    }
    $login = Invoke-WebRequest -UseBasicParsing -Uri $uri -Body $webCredential -Method Post -SessionVariable pfWebSession | Out-Null
    return [pscustomobject] @{     
        'pfWebSession' = $pfWebSession
        'dictOptions' = $dictOptions
    }
}


Function Post-request{
    <#
    This Function uploads data to the pfsensen, mostly used for logout
    #>
    Param
    (
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,
        [Parameter(Mandatory=$true, Position=1,HelpMessage='The PostData as a Dictonary')] [PSObject] $dictPostData,
        [Parameter(Mandatory=$true, Position=2,HelpMessage='The Uri Get extension to setup the connection')] [PSObject] $UriGetExtension, 
        [Parameter(Mandatory=$true, Position=3,HelpMessage='The Uri post extension for the post request')] [PSObject] $UriPostExtension
    )
    [bool] $NoTLS = $Connection.dictOptions.NoTLS
    [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Connection.pfWebSession
    $uri = 'https://{0}/{1}' -f $Server, $UriGetExtension
    If ($NoTLS) 
    {
        $uri = $uri -Replace "^https:",'http:'
        Write-debug -Message 'WARNING NO TLS SECURTIY!!! '
    }
    $request = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Get -WebSession $webSession
    $dictPostData.add("__csrf_magic","$($request.InputFields[0].Value)")
    $uri = $uri -replace $UriGetExtension,$UriPostExtension
    Try
    {
        $rawRet = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Post -Body $dictPostData -WebSession $webSession -EA Stop
    }
    Catch
    {
        Write-Error -Message 'Something went wrong Posting the data'
    }
    try{
        $error_statement = $rawRet.ParsedHtml.body.getElementsByClassName("alert alert-danger input-errors")
        $error_alert = $error_statement | %{$_.InnerText}
        if ($error_alert){Write-Warning $error_alert -WarningAction Inquire}}
    catch{}
}


Function download-xml{
    <#
    Download's the full xml config from the pfsense
    With the NoTLS switch port 80 can be used instead of 443
    #>
    Param(
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection)
    [bool] $NoTLS = $Connection.dictOptions.NoTLS
    [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Connection.pfWebSession
    $uri = 'https://{0}/diag_backup.php' -f $Server
    If ($NoTLS) 
    {
        $uri = $uri -Replace "^https:",'http:'
        Write-debug -Message 'WARNING NO TLS SECURTIY!!! '
    }
    $request = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Get -WebSession $webSession
    Try
    {
        $boundry = "-----" + [System.Guid]::NewGuid().ToString()
        $LF = "`r`n" 
        $bodyLines = (
        "--$boundry",
        "Content-Disposition: form-data; name=`"__csrf_magic`"",
        '',
        $($request.InputFields[0].Value),
        "--$boundry",
        "Content-Disposition: form-data; name=`"backuparea`"",
        '',
        '',
        "--$boundry",
        "Content-Disposition: form-data; name=`"donotbackuprrd`"",
        '',
        'Yes',
        "--$boundry",
        "Content-Disposition: form-data; name=`"encrypt_password`"",
        '',
        '',
        "--$boundry",
        "Content-Disposition: form-data; name=`"download`"",
        '',
        'Download configuration as XML',
        "--$boundry",
        "Content-Disposition: form-data; name=`"restorearea`"",
        '',
        '',
        "--$boundry",
        "Content-Disposition: form-data; name=`"conffile`"; filename=`"`"",
        "Content-Type: application/octet-stream",
        '',
        '(binary)',
        "--$boundry",
        "Content-Disposition: form-data; name=`"decrypt_password`"",
        '',
        '',
        "--$boundry--"
        ) 
        $bodyLines = $bodyLines -join $LF
        $rawRet = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Post -Body $bodyLines -WebSession $webSession -ContentType "multipart/form-data; boundary=$boundry" 
    }
    Catch
    {
        Write-Error -Message 'Something went wrong Posting the data'
    }
    try{
    $error_statement = $rawRet.ParsedHtml.body.getElementsByClassName("alert alert-danger input-errors")
    $error_alert = $error_statement | %{$_.InnerText}
    if ($error_alert){Write-Warning $error_alert -WarningAction Inquire}}
    catch{}
    $rawRet
}


Function upload-xml{
    <#
    Uploads a XML file to the pfsense
    With the NoTLS switch port 80 can be used instead of 443
    #>
    Param(
        [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,
        [Parameter(Mandatory=$true, Position=1,HelpMessage='The PostData as a Dictonary')] [PSObject] $dictPostData,
        [Parameter(Mandatory=$true, Position=2,HelpMessage='The Uri Get extension to setup the connection')] [PSObject] $UriGetExtension, 
        [Parameter(Mandatory=$true, Position=2,HelpMessage='The Uri post extension for the post request')] [PSObject] $UriPostExtension)
    [bool] $NoTLS = $Connection.dictOptions.NoTLS
    [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Connection.pfWebSession
    $uri = 'https://{0}/{1}' -f $Server, $UriGetExtension
    If ($NoTLS) 
    {
        $uri = $uri -Replace "^https:",'http:'
        Write-debug -Message 'WARNING NO TLS SECURTIY!!! '
    }
    $request = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Get -WebSession $webSession
    $dictPostData.add("__csrf_magic","$($request.InputFields[0].Value)")
    $uri = $uri -replace $UriGetExtension,$UriPostExtension
    Try
    {
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
        "Content-Disposition: form-data; name=`"donotbackuprrd`"",
        '',
        $dictPostData.item("donotbackuprrd"),
        "--$boundry",
        "Content-Disposition: form-data; name=`"encrypt_password`"",
        '',
        $dictPostData.item("encrypt_password"),
        "--$boundry",
        "Content-Disposition: form-data; name=`"restorearea`"",
        '',
        $dictPostData.item("restorearea"),
        "--$boundry",
        "Content-Disposition: form-data; name=`"conffile`"; filename=`"$($dictPostData.item("filename"))`"",
        "Content-Type: text/xml",
        '',
        $dictPostData.item("conffile"),
        "--$boundry",
        "Content-Disposition: form-data; name=`"decrypt_password`"",
        '',
        $dictPostData.item("decrypt_password"),
        "--$boundry",
        "Content-Disposition: form-data; name=`"restore`"",
        '',
        $dictPostData.item("restore"),
        "--$boundry--",
        ""
        ) 
        $bodyLinesjoind = $bodyLines -join $LF
#       $uri = "http://192.168.0.1/diag_backup.php"
        $rawRet = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Post -Body $bodyLinesjoind -WebSession $webSession -ContentType "multipart/form-data; boundary=$boundry" 
    }
    Catch
    {
        Write-Error -Message 'Something went wrong Posting the data'
    }
    try{
    $error_statement = $rawRet.ParsedHtml.body.getElementsByClassName("alert alert-danger input-errors")
    $error_alert = $error_statement | %{$_.InnerText}
    if ($error_alert){Write-Warning $error_alert -WarningAction Inquire}}
    catch{}
    $rawRet
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
        Write-debug -Message 'WARNING NO TLS SECURTIY!!! '
    }
    $request = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Get -WebSession $webSession
    return $request
}


function convertxml{
    Param([Parameter(Mandatory=$true, Position=1,HelpMessage='the xml file')][xml]$xml)
    $StringWriter = New-Object System.IO.StringWriter;
    $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter;
    $XmlWriter.Formatting = "indented";
    $xml.WriteTo($XmlWriter);
    $XmlWriter.Flush();
    $StringWriter.Flush();
    $Output = $StringWriter.ToString();
    return $Output
}


Function Logout {
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject]$Connection)
    $dictPostData = @{logout=""}
    Post-request -Connection @Connection -dictPostData $dictPostData -UriGetExtension "index.php" -UriPostExtension "index.php"
}


Function Printe_route{
# api_through_json.ps1 -server '192.168.0.1' -username 'admin' -Password 'pfsense' -service route -Action print -NoTLS -NoTest
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $Data = download-xml -Connection @Connection
    [xml]$XML_Data = $Data.RawContent.Substring($($Data.RawContent.IndexOf("<")))
    Write-Host "Static routes are:" -BackgroundColor White -ForegroundColor Black
    Write-Host "Network : Gateway : Description`n`r" -BackgroundColor White -ForegroundColor Black
    $routeindex = 0
    try{
        if($XML_Data.pfsense.staticroutes.route[$routeindex]){
            while($XML_Data.pfsense.staticroutes.route[$routeindex]){
                "{0} : {1} : {2}" -f`
                $XML_Data.pfsense.staticroutes.route[$routeindex].Network,`
                $XML_Data.pfsense.staticroutes.route[$routeindex].gateway,`
                $XML_Data.pfsense.staticroutes.route[$routeindex].descr.'#cdata-section'
                $routeindex++
            }
        }
        else{"{0} : {1} : {2}" -f $XML_Data.pfsense.staticroutes.route.Network,$XML_Data.pfsense.staticroutes.route.gateway,$XML_Data.pfsense.staticroutes.route.descr.'#cdata-section'}
    }catch{Write-host "No Static routes Found"}

}


Function Add_route{
# api_through_json.ps1 -server '192.168.0.1' -username 'admin' -Password 'pfsense' -service route -Action add 192.168.11.0/22 WAN_DHCP "This is another test" -NoTLS -NoTest
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='Network/subnet')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='Gateway')] [PSObject] $Argument2,
    [Parameter(Mandatory=$true, Position=3,HelpMessage='Discription')] [PSObject] $Argument3)
    $Data = download-xml -Connection @Connection
    $XML_Data = [xml]$Data.RawContent.Substring($Data.RawContent.IndexOf("<"))

    $select_xml = $XML_Data.pfsense.staticroutes
    try{
        $xml_upload = New-Object -TypeName xml
        $xml_upload.AppendChild($xml_upload.ImportNode($select_xml,$true))
        try{
            $XML_NEW = $xml_upload.staticroutes.route[0].clone()
        }
        catch{
            $XML_NEW = $xml_upload.staticroutes.route.clone()
        }
        $XML_NEW.network = $("{0}" -f $Argument1)
        $XML_NEW.gateway = $("{0}" -f $Argument2)
        $XML_NEW.descr.InnerText = $("{0}" -f $Argument3)
        $xml_upload.DocumentElement.AppendChild($XML_NEW)
    }
    catch{
        [xml]$xml_upload = New-Object system.Xml.XmlDocument
        $xml_upload.LoadXml("<?xml version=`"1.0`" encoding=`"utf-8`"?><staticroutes></staticroutes>")
        $xmlElt = $xml_upload.CreateElement("route")
        $xmlSubElt = $xml_upload.CreateElement("network")
        $xmlElt.AppendChild($xmlSubElt) | out-null
        $xmlSubElt = $xml_upload.CreateElement("gateway")
        $xmlElt.AppendChild($xmlSubElt) | out-null
        $xmlSubElt = $xml_upload.CreateElement("descr")
        $xmlElt.AppendChild($xmlSubElt) | out-null
        $xml_upload.LastChild.AppendChild($xmlElt) | out-null
        $xml_upload.staticroutes.route.network = $("{0}" -f $Argument1)
        $xml_upload.staticroutes.route.gateway = $("{0}" -f $Argument2)
        $xml_upload.staticroutes.route.descr = $("{0}" -f $Argument3)
    }
    $xml_string = convertxml -xml $xml_upload
    $dictPostData = @{
        backuparea = ""
        donotbackuprrd = "Yes"
        encrypt_password = ""
        restorearea = "staticroutes"
        conffile = $xml_string
        filename = "route.xml"
        decrypt_password = ""
        restore = "Restore Configuration"}
    $uploaded = upload-xml -Connection @Connection -dictPostData $dictPostData -UriGetExtension "diag_backup.php" -UriPostExtension "diag_backup.php"
}


# ToDo: Does not delete the last static route
Function delete_route{
#pfsense_api -server '' -username '' -Password '' -service Route -action Delete "192.168.0.0/24" WAN_DHCP 
    Param(
    [Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')] [PSObject] $Connection,   
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument1,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Argument you would like to give to the action')] [PSObject] $Argument2)
    $Data = download-xml -Connection @Connection
    $XML_Data = [xml]$Data.RawContent.Substring($Data.RawContent.IndexOf("<"))
    $select_xml = $XML_Data.pfsense.staticroutes
    $xml_upload = New-Object -TypeName xml
    $xml_upload.AppendChild($xml_upload.ImportNode($select_xml,$true)) | out-null
    ($xml_upload.staticroutes.route | Where-Object {($_.network -contains $("{0}" -f $Argument1)) -and ($_.gateway -contains $("{0}" -f $Argument2) )}) | ForEach-Object {[void]$_.ParentNode.RemoveChild($_)}
    $xml_string = convertxml -xml $xml_upload
    $dictPostData = @{
        backuparea = ""
        donotbackuprrd = "Yes"
        encrypt_password = ""
        restorearea = "staticroutes"
        conffile = $xml_string
        filename = "route.xml"
        decrypt_password = ""
        restore = "Restore Configuration"}
    $uploaded = upload-xml -Connection @Connection -dictPostData $dictPostData -UriGetExtension "diag_backup.php" -UriPostExtension "diag_backup.php"
}


# ToDo: no / symbol if dhcp
Function print_interface {
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $Data = download-xml -Connection @Connection
    [xml]$XML_Data = $Data.RawContent.Substring($($Data.RawContent.IndexOf("<")))
    Write-Host "interfaces are:" -BackgroundColor White -ForegroundColor Black
    Write-Host "Internal name : Userdifend name :  IPv4  :  IPv6  : Gateway`n`r" -BackgroundColor White -ForegroundColor Black
    $XML_Data.pfsense.interfaces.ChildNodes.name | %{"{0} : {1} : {2}/{3} : {4}/{5} : {6}" -f `        $XML_Data.pfsense.interfaces.$_.name,`        $XML_Data.pfsense.interfaces.$_.descr.'#cdata-section',`
        $XML_Data.pfsense.interfaces.$_.ipaddr,`        $XML_Data.pfsense.interfaces.$_.subnet,        $XML_Data.pfsense.interfaces.$_.ipaddrv6,`        $XML_Data.pfsense.interfaces.$_.subnetv6,`        $XML_Data.pfsense.interfaces.$_.gateway }
}


Function print_Gateway{
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $Data = download-xml -Connection @Connection
    [xml]$XML_Data = $Data.RawContent.Substring($($Data.RawContent.IndexOf("<")))
    Write-Host "DHCP Gateway's are:" -BackgroundColor White -ForegroundColor Black
    $XML_Data.pfsense.interfaces.ChildNodes.name | %{if ($XML_Data.pfsense.interfaces.$_.ipaddr -eq "dhcp"){"{0}_DHCP" -f $XML_Data.pfsense.interfaces.$_.name}}
    Write-Host "`n`rconfigured Gateway's are:" -BackgroundColor White -ForegroundColor Black
    Write-Host "Name : Interface : Gateway IP : Monitor IP : Description`n`r" -BackgroundColor White -ForegroundColor Black
    try{
        $gatewayindex = 0
        if($XML_Data.pfsense.gateways.gateway_item[$gatewayindex]){
            while($XML_Data.pfsense.gateways.gateway_item[$gatewayindex]){
                "{0} : {1} : {2} : {3} : {4}" -f `
                $XML_Data.pfsense.gateways.gateway_item[$gatewayindex].name,`
                $(if($XML_Data.pfsense.interfaces.$($XML_Data.pfsense.gateways.gateway_item[$gatewayindex].interface).SelectSingleNode("descr")){$XML_Data.pfsense.interfaces.$($XML_Data.pfsense.gateways.gateway_item[$gatewayindex].interface).descr.'#cdata-section'}else{$XML_Data.pfsense.gateways.gateway_item[$gatewayindex].interface}),`
                $XML_Data.pfsense.gateways.gateway_item[$gatewayindex].gateway,`
                $(if($XML_Data.pfsense.gateways.gateway_item[$gatewayindex].SelectSingleNode("monitor")){$XML_Data.pfsense.gateways.gateway_item[$gatewayindex].monitor}else{$XML_Data.pfsense.gateways.gateway_item[$gatewayindex].gateway}),`
                $XML_Data.pfsense.gateways.gateway_item[$gatewayindex].descr.'#cdata-section'
                $gatewayindex++
            }
        }
        else{"{0} : {1} : {2} : {3} : {4}" -f `
            $XML_Data.pfsense.gateways.gateway_item.name,`
            $XML_Data.pfsense.interfaces.$($XML_Data.pfsense.gateways.gateway_item.interface).descr.'#cdata-section',` # ToDo: if default name use default
            $(if($XML_Data.pfsense.interfaces.$($XML_Data.pfsense.gateways.gateway_item.interface).SelectSingleNode("descr")){$XML_Data.pfsense.interfaces.$($XML_Data.pfsense.gateways.gateway_item.interface).descr.'#cdata-section'}else{$XML_Data.pfsense.gateways.gateway_item.interface}),`
            $XML_Data.pfsense.gateways.gateway_item.gateway,`
            $(if($XML_Data.pfsense.gateways.gateway_item.SelectSingleNode("monitor")){$XML_Data.pfsense.gateways.gateway_item.monitor}else{$XML_Data.pfsense.gateways.gateway_item.gateway}),`
            $XML_Data.pfsense.gateways.gateway_item.descr.'#cdata-section'}
    }catch{Write-Host "No gateway's configured by user"}
    Write-Host "`n`rDefault Gateway is:" -BackgroundColor White -ForegroundColor Black
    try{
        if($XML_Data.pfsense.gateways.SelectSingleNode("defaultgw4" -ne "")){"IPv4 Gateway: {0}" -f $XML_Data.pfsense.gateways.defaultgw4}
        elseif($XML_Data.pfsense.gateways.defaultgw4 -eq "-"){write-host "IPv4 Gateway: None"}
        else{write-host "IPv4 Gateway: Automatic"}}
    catch{write-host "IPv4 Gateway: Automatic"}
    try{
        if($XML_Data.pfsense.gateways.SelectSingleNode("defaultgw6" -ne "")){"IPv6 Gateway: {0}" -f $XML_Data.pfsense.gateways.defaultgw6}
        elseif($XML_Data.pfsense.gateways.defaultgw6 -eq "-"){write-host "IPv6 Gateway: None"}
        else{write-host "IPv6 Gateway: Automatic"}}
    catch{write-host "IPv6 Gateway: Automatic"}
}



Function add_Gateway{}


# ToDo: convert local interface name's to user defined interface name
Function print_dnsresolver{
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $Data = download-xml -Connection @Connection
    [xml]$XML_Data = $Data.RawContent.Substring($($Data.RawContent.IndexOf("<")))
    Write-Host "Dns Server settings are:" -BackgroundColor White -ForegroundColor Black
    "Enabled: {0} | Active interfaces: {1} | Outgoing interfaces: {2} | Port: {3} | Sslport: {4} | dnssec: {5}" -f `
    $(if($XML_Data.pfsense.unbound.SelectSingleNode("enable")){"Yes"}Else{"No"}),`
    $(if($XML_Data.pfsense.unbound.active_interface -eq ""){"all"}else{$XML_Data.pfsense.unbound.active_interface}),`
    $(if($XML_Data.pfsense.unbound.outgoing_interface -eq ""){"all"}else{$XML_Data.pfsense.unbound.outgoing_interface}),`
    $(if(($XML_Data.pfsense.unbound.port -eq "") -or -not ($XML_Data.pfsense.unbound.SelectSingleNode("port"))){"53"}else{$XML_Data.pfsense.unbound.port}),`
    $(if(($XML_Data.pfsense.unbound.sslport -eq "") -or -not ($XML_Data.pfsense.unbound.SelectSingleNode("sslport"))){"853"}else{$XML_Data.pfsense.unbound.sslport}),`
    $(if($XML_Data.pfsense.unbound.SelectSingleNode("dnssec")){"Yes"}Else{"No"})
    if($XML_Data.pfsense.unbound.SelectSingleNode("hosts")){
        $hostindex = 0
        if($XML_Data.pfsense.unbound.hosts[$hostindex]){
            Write-Host "`n`rHost override's:" -BackgroundColor White -ForegroundColor Black
            Write-Host "Host : Domain : IPaddress : Description : Alias Hostname : Alias Domain : Alias description" -BackgroundColor White -ForegroundColor Black
            while($XML_Data.pfsense.unbound.hosts[$hostindex].host){
                "`n`r{0} : {1} : {2} : {3}" -f `
                $($XML_Data.pfsense.unbound.hosts[$hostindex].host),`
                $($XML_Data.pfsense.unbound.hosts[$hostindex].domain),`
                $($XML_Data.pfsense.unbound.hosts[$hostindex].ip),`
                $($XML_Data.pfsense.unbound.hosts[$hostindex].descr.'#cdata-section')
                try{
                if($XML_Data.pfsense.unbound.hosts[$hostindex].aliases.SelectSingleNode("item")){
                    $aliasindex = 0
                    if($XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item[$aliasindex]){
                        while($XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item[$aliasindex]){
                            "{0} : {1} : {2} : {3} : {4} : {5} : {6}" -f `
                            $($XML_Data.pfsense.unbound.hosts[$hostindex].host),`
                            $($XML_Data.pfsense.unbound.hosts[$hostindex].domain),`
                            $($XML_Data.pfsense.unbound.hosts[$hostindex].ip),`
                            $($XML_Data.pfsense.unbound.hosts[$hostindex].descr.'#cdata-section'),`
                            $XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item[$aliasindex].host,`
                            $XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item[$aliasindex].domain,`
                            $XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item[$aliasindex].description.'#cdata-section'
                            $aliasindex++
                        }
                    }
                    else{
                        "{0} : {1} : {2} : {3} : {4} : {5} : {6}" -f `
                        $($XML_Data.pfsense.unbound.hosts[$hostindex].host),`
                        $($XML_Data.pfsense.unbound.hosts[$hostindex].domain),`
                        $($XML_Data.pfsense.unbound.hosts[$hostindex].ip),`
                        $($XML_Data.pfsense.unbound.hosts[$hostindex].descr.'#cdata-section'),`
                        $XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item.host,`
                        $XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item.domain,`
                        $XML_Data.pfsense.unbound.hosts[$hostindex].aliases.item.description.'#cdata-section'            
                    }     
                }else{}
                }catch{}

                $hostindex++
            }
        }else{
            Write-Host "`n`rHost override's:" -BackgroundColor White -ForegroundColor Black
            Write-Host "Host : Domain : IPaddress : Description : Alias Hostname : Alias Domain : Alias description" -BackgroundColor White -ForegroundColor Black
            "{0} : {1} : {2} : {3}" -f `
            $($XML_Data.pfsense.unbound.hosts.host),`
            $($XML_Data.pfsense.unbound.hosts.domain),`
            $($XML_Data.pfsense.unbound.hosts.ip),`
            $($XML_Data.pfsense.unbound.hosts.descr.'#cdata-section')
            if($XML_Data.pfsense.unbound.hosts.SelectSingleNode("aliases")){
                $aliasindex = 0
                try{
                    if($XML_Data.pfsense.unbound.hosts.aliases.item[$aliasindex]){
                        while($XML_Data.pfsense.unbound.hosts.aliases.item[$aliasindex]){
                            "{0} : {1} : {2} : {3} : {4} : {5} : {6}" -f `
                            $($XML_Data.pfsense.unbound.hosts.host),`
                            $($XML_Data.pfsense.unbound.hosts.domain),`
                            $($XML_Data.pfsense.unbound.hosts.ip),`
                            $($XML_Data.pfsense.unbound.hosts.descr.'#cdata-section'),`
                            $XML_Data.pfsense.unbound.hosts.aliases.item[$aliasindex].host,`
                            $XML_Data.pfsense.unbound.hosts.aliases.item[$aliasindex].domain,`
                            $XML_Data.pfsense.unbound.hosts.aliases.item[$aliasindex].description.'#cdata-section'
                            $aliasindex++
                        }
                    }
                    else{
                        "{0} : {1} : {2} : {3} : {4} : {5} : {6}" -f `
                        $($XML_Data.pfsense.unbound.hosts.host),`
                        $($XML_Data.pfsense.unbound.hosts.domain),`
                        $($XML_Data.pfsense.unbound.hosts.ip),`
                        $($XML_Data.pfsense.unbound.hosts.descr.'#cdata-section'),`
                        $XML_Data.pfsense.unbound.hosts.aliases.item.host,`
                        $XML_Data.pfsense.unbound.hosts.aliases.item.domain,`
                        $XML_Data.pfsense.unbound.hosts.aliases.item.description.'#cdata-section'           
                    }
                }catch{}    
            }
        }
    }
    if($XML_Data.pfsense.unbound.SelectSingleNode("domainoverrides")){
        $domainindex = 0
        if($XML_Data.pfsense.unbound.domainoverrides[$domainindex]){
            Write-Host "`n`rDomain override's:" -BackgroundColor White -ForegroundColor Black
            Write-Host "Domain : Server IPaddress : TLS Hostname : Description" -BackgroundColor White -ForegroundColor Black
            "{0} : {1} : {2}" -f `
            $XML_Data.pfsense.unbound.domainoverrides[$domainindex].domain,`
            $XML_Data.pfsense.unbound.domainoverrides[$domainindex].ip,`
            $XML_Data.pfsense.unbound.domainoverrides[$domainindex].descr.'#cdata-section',`
            $XML_Data.pfsense.unbound.domainoverrides[$domainindex].tls_hostname
        }

    }
    if($XML_Data.pfsense.unbound.SelectSingleNode("custom_options")){
    Write-Host "`n`rCustom options are:" -BackgroundColor White -ForegroundColor Black
    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($XML_Data.pfsense.unbound.custom_options))
    }
    # Converting active interface name's to user defined name's
#    $XML_Data.pfsense.unbound.active_interface -split "," | %{
#        if($_ -eq "lo0"){"Localhost"}
#        try{if($XML_Data.pfsense.interfaces.$_.SelectNodes("descr")){$XML_Data.pfsense.interfaces.$_.descr}
#        }catch{$XML_Data.pfsense.interfaces.$_.Name}
#    }
}


Function print_portfwd {
    Param([Parameter(Mandatory=$true, Position=0,HelpMessage='Valid/active websession to server')][PSObject]$Connection) 
    $Data = download-xml -Connection @Connection
    [xml]$XML_Data = $Data.RawContent.Substring($($Data.RawContent.IndexOf("<")))
    Write-Host "Port Forwarders are:" -BackgroundColor White -ForegroundColor Black
    Write-Host "Interface : Protocol : Source Address : Source Ports : Dest. Address : Dest. Ports : NAT IP : NAT Ports : Description`n`r" -BackgroundColor White -ForegroundColor Black
    $natindex = 0
    try{
        if($XML_Data.pfsense.nat.rule[$natindex]){
            while($XML_Data.pfsense.nat.rule[$natindex]){
                "{0} : {1} : {2} : {3} : {4} : {5} : {6} : {7} : {8}" -f`
                $XML_Data.pfsense.interfaces.$($XML_Data.pfsense.nat.rule[$natindex].interface).descr.'#cdata-section',` # ToDo: if default name use default
                $XML_Data.pfsense.nat.rule[$natindex].protocol,`
                $(if($XML_Data.pfsense.nat.rule[$natindex].source.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule[$natindex].source.address}),`
                $(if($XML_Data.pfsense.nat.rule[$natindex].source.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule[$natindex].source.port}),`
                $(if($XML_Data.pfsense.nat.rule[$natindex].destination.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule[$natindex].destination.address}),`
                $(if($XML_Data.pfsense.nat.rule[$natindex].destination.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule[$natindex].destination.port}),`
                $XML_Data.pfsense.nat.rule[$natindex].target,`
                $XML_Data.pfsense.nat.rule[$natindex]."local-port",`
                $XML_Data.pfsense.nat.rule[$natindex].descr.'#cdata-section'
                $natindex++
            }
        }
        else{"{0} : {1} : {2} : {3} : {4} : {5} : {6} : {7} : {8}" -f`
            $XML_Data.pfsense.interfaces.$($XML_Data.pfsense.nat.rule.interface).descr.'#cdata-section',` # ToDo: if default name use default
            $XML_Data.pfsense.nat.rule.protocol,`
            $(if($XML_Data.pfsense.nat.rule.source.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule.source.address}),`
            $(if($XML_Data.pfsense.nat.rule.source.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule.source.port}),`
            $(if($XML_Data.pfsense.nat.rule.destination.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule.destination.address}),`
            $(if($XML_Data.pfsense.nat.rule.destination.SelectSingleNode("any")){"Any"}else{"{0}" -f $XML_Data.pfsense.nat.rule.destination.port}),`
            $XML_Data.pfsense.nat.rule.target,`
            $XML_Data.pfsense.nat.rule."local-port",`
            $XML_Data.pfsense.nat.rule.descr.'#cdata-section'
        }
    }
    catch{Write-host "No NAT rule's found"}
}


Function print_Alias{}


Function print_Vip{}


Function print_Firewall{}



# $server = "192.168.0.1" ; $Username = "admin" ; $password = "pfsense"
$DefaulkCred  = New-Object System.Management.Automation.PSCredential ($Username, $(ConvertTo-SecureString -string $password -AsPlainText -Force))

# $Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS


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
    elseif($service -eq "Firewall"){$ManFirewall ; exit}

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
    elseif ($action -eq "add"){add_route -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 | out-null}
    elseif ($action -eq "delete"){delete_route -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2}  
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

elseif ($service -eq "Firewall"){
       if ($action -eq "print"){print_Firewall -Connection @Connection}
       elseif ($action -eq "add"){addrule_Firewall -Connection @Connection -Argument1 $Argument1 -Argument2 $Argument2 -Argument3 $Argument3 -argument4 $Argument4 -argument5 $Argument5 -Argument6 $Argument6 -Argument7 $Argument7 -Argument8 $Argument8 -Argument9 $Argument9 -Argument10 $Argument10 -Argument11 $Argument11 -Argument12 $Argument12 -Argument13 $Argument13 -Argument14 $Argument14 }

}

else{"Dit not find {0} please use `"-Server '' -Username '' -Password '' Help`" to see which ones are supported" -f $service}


if ($Connection){Logout -Connection @Connection}