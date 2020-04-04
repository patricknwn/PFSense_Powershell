Param
    (
    [Parameter(Mandatory=$true, Position=0,HelpMessage='The Server address')] [PSObject] $Server,
    [Parameter(Mandatory=$true, Position=1,HelpMessage='The Username')] [PSObject] $Username,
    [Parameter(Mandatory=$true, Position=2,HelpMessage='The Password')] [PSObject] $password,
    [Parameter(Mandatory=$false, Position=3,HelpMessage='The service you would like to talke to')] [PSObject] $service,
    [Parameter(Mandatory=$false, Position=4,HelpMessage='The action you would like to do on the service')] [PSObject] $Action,
    [Switch] $NoTLS
    )

. .\man.ps1

If(-not $pfsense_credentials){
    $Secpassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    $pfsense_credentials = New-Object System.Management.Automation.PSCredential($username,$Secpassword)
}

$uri = "https://{0}/xmlrpc.php" -f $server
If ($NoTLS) 
{
    $uri = $uri -Replace "^https:",'http:'
    Write-Warning -Message 'WARNING NO TLS SECURTIY!!! '
}

function convertxml{
    Param([Parameter(Mandatory=$true, Position=1,HelpMessage='the xml file')]$xml)
    $StringWriter = New-Object System.IO.StringWriter;
    $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter;
    $XmlWriter.Formatting = "indented";
    $xml.WriteTo($XmlWriter);
    $XmlWriter.Flush();
    $StringWriter.Flush();
    $Output = $StringWriter.ToString();
    return $Output
}

Function download-xml{
    ([Parameter(Mandatory=$true, Position=0,HelpMessage="the php command to execute")] $php_command)
    $request_body = "<?xml version='1.0' encoding='iso-8859-1'?><methodCall><methodName>pfsense.exec_php</methodName><params><param><value><string>$php_command</string></value></param></params></methodCall>"
    $response = Invoke-Webrequest  -UseBasicParsing -Authentication basic -Credential $pfsense_credentials -AllowUnencryptedAuthentication `
        -ContentType 'text/xml' `
        -Uri $uri `
        -Method POST `
        -Body $request_body
    "{0}" -f $response.Content
    $response
}

Function Printe_route{
# PFsense_api_xml_rpc.ps1 -server '192.168.0.1' -username 'admin' -Password 'pfsense' -service route -Action print -NoTLS
    $php_command = "global `$config; `$toreturn=`$config['staticroutes'];"
    $Data = [XML]$(download-xml -php_command $php_command).Content
    Write-Host "Static routes are:" -BackgroundColor White -ForegroundColor Black
    Write-Host "Network : Gateway : Description`n`r" -BackgroundColor White -ForegroundColor Black
    $staticroutes = $($Data | Select-Xml -XPath "/methodResponse/params/param/value/struct/member/value/array/data/value")
    $routeindex = 0
    try{
        if($staticroutes[$routeindex]){
            while($staticroutes[$routeindex]){
                "{0} : {1} : {2}" -f`
                $staticroutes[$routeindex].Node.struct.member.value[0].string,`
                $staticroutes[$routeindex].Node.struct.member.value[1].string,`
                $staticroutes[$routeindex].Node.struct.member.value[2].string
                $routeindex++
            }
        }
        else{"{0} : {1} : {2}" -f $staticroutes.Node.struct.member.value[0].string,$staticroutes.Node.struct.member.value[1].string,$staticroutes.Node.struct.member.value[2].string}
    }catch{Write-host "No Static routes Found"}
}

function  print_interface {
    $php_command = "global `$config; `$toreturn=`$config['interfaces'];"
    $Data = [XML]$(download-xml -php_command $php_command).Content
    Write-Host "Interfaces are:" -BackgroundColor White -ForegroundColor Black
    Write-Host "Name : Gateway : Description`n`r" -BackgroundColor White -ForegroundColor Black
    $interfaces = $data.methodResponse.params.param.value.struct.member
    $interfaces[0].value.struct.member[0].name
    $interindex = 0
    try{
        if($interfaces[$interindex].name){
            while($interfaces[$interindex].name){
                "{0} : {1} : {2}" -f`
                $interfaces[$interindex].name,`
                $interfaces[$interindex].name,`
                $interfaces[$interindex].name
                $interindex++
            }
        }
        else{"{0} : {1} : {2}" -f $interfaces.name,$interfaces.name,$interfaces.name}
    }catch{Write-host "No Interfaces found"}
}

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


if ($service -eq "route"){
    if ($action -eq "print"){Printe_route}
    elseif ($action -eq "add"){add_route}
    elseif ($action -eq "delete"){delete_route}  
}
elseif ($service -eq "Interface"){
    if ($action -eq "print"){print_interface}
}
elseif ($service -eq "Gateway"){
    if ($action -eq "print"){print_Gateway}
    elseif ($action -eq "add"){add_Gateway }
    elseif ($action -eq "delete"){delete_Gateway}
    elseif ($action -eq "default"){default_Gateway}
}
elseif ($service -eq "dnsresolver"){
    if ($action -eq "print"){print_dnsresolver}
    elseif ($action -eq "UploadCustom"){UploadCustom_dnsresolver}
    elseif ($action -eq "addhost"){addhost_dnsresolver}
    elseif ($action -eq "Deletehost"){Deletehost_dnsresolver}
    elseif ($action -eq "adddomain"){adddomain_dnsresolver}
    elseif ($action -eq "deletedomain"){deletedomain_dnsresolver}
}
elseif ($service -eq "portfwd"){
    if ($action -eq "print"){print_portfwd}
    elseif ($action -eq "Add"){add_portfwd}
    elseif ($action -eq "Delete"){Delete_portfwd}
}
elseif ($service -eq "Alias"){
    if ($action -eq "print"){print_Alias}
    elseif ($action -eq "PrintSpecific"){SpecificPrint_Alias}
    elseif ($action -eq "add"){add_Alias}
    elseif ($action -eq "delete"){delete_Alias}
    elseif ($action -eq "addvalue"){addvalue_Alias}
    elseif ($action -eq "deletevalue"){deletevalue_Alias}
}
elseif ($service -eq "Vip"){
    if ($action -eq "print"){print_Vip}
    elseif ($Action -eq "add"){add_Vip}
    elseif ($Action -eq "delete"){delete_Vip}
}
elseif ($service -eq "Firewall"){
    if ($action -eq "print"){print_Firewall}
    elseif ($action -eq "add"){addrule_Firewall}
}
else{"Dit not find {0} please use `"-Server '' -Username '' -Password '' Help`" to see which ones are supported" -f $service}
# for example, fetch all the DNS servers
#[XML]$response.Content | Select-XML -XPath "//member[name='dnsserver']//string" | ForEach-Object { $_.Node.'#text' }

# reduce the output to only the requested section:
#$php_command = "global `$config; `$toreturn=`$config['system']['staticroutes'];"
#$request_body = "<?xml version='1.0' encoding='iso-8859-1'?><methodCall><methodName>pfsense.exec_php</methodName><params><param><value><string>$php_command</string></value></param></params></methodCall>"

#$response = Invoke-Webrequest  -UseBasicParsing -Authentication basic -Credential $pfsense_credentials -AllowUnencryptedAuthentication `
#    -ContentType 'text/xml' `
#    -Uri ("http://{0}/xmlrpc.php" -f $server) `
#    -Method POST `
#    -Body $request_body

# for example, fetch all the DNS servers
#[XML]$response.Content | Select-XML -XPath "//string" | ForEach-Object { $_.Node.'#text' }