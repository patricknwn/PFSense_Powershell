Param
    (
    [Parameter(Mandatory=$true, Position=0,
    HelpMessage='The Server address'
    )] [PSObject] $Server,
    [Parameter(Mandatory=$true, Position=1,
    HelpMessage='The Username'
    )] [PSObject] $Username,
    [Parameter(Mandatory=$true, Position=2,
    HelpMessage='Password'
    )] [PSObject] $Password,
    [Switch] $NoTest,
    [Switch] $NoTLS
)

Function test-connection{
    <#
    This function test's if the pfsense is online by trying to connect to the webserver.
    it accept's the NoTLS switch parameter with you can use if the pfsense uses port 80.
    If the Reboot switch is given the function wait's till the pfsense is back online afther the reboot.
    #>
    Param
    (     
        [Parameter(Mandatory=$true, Position=0,
        HelpMessage='Server'
        )] [PSObject] $Server,
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
    #>
    Param
    (
        [Parameter(Mandatory=$true, Position=0,
                HelpMessage='Server'
        )] [PSObject] $Server,
        [Parameter(Mandatory=$true, Position=1,
                HelpMessage='Credentials'
        )] [PSObject] $Credentials,
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
    $login = Invoke-WebRequest -Uri $uri -Body $webCredential -Method Post -SessionVariable pfWebSession # | Out-Null
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
        [Parameter(Mandatory=$true, Position=0,
                HelpMessage='Valid/active websession to server'
        )] [PSObject] $Session,
        [Parameter(Mandatory=$true, Position=1,
                HelpMessage='The PostData as a Dictonary'
        )] [PSObject] $dictPostData,
        [Parameter(Mandatory=$true, Position=2,
        HelpMessage='The Uri Get extension to setup the connection'
        )] [PSObject] $UriGetExtension, 
        [Parameter(Mandatory=$true, Position=2,
        HelpMessage='The Uri post extension for the post request'
        )] [PSObject] $UriPostExtension,
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
        [Parameter(Mandatory=$true, Position=0,
        HelpMessage='Valid/active websession to server'
        )] [PSObject] $Session,
        [Parameter(Mandatory=$true, Position=1,
        HelpMessage='The Uri Get extension'
        )] [PSObject] $UriGetExtension 
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

Function create-dictdata{
    Param
    (
        [Parameter(Mandatory=$true, Position=0,
        HelpMessage='Valid/active websession to server'
        )] [PSObject] $Session,
        [Parameter(Mandatory=$true, Position=1,
        HelpMessage='The Content of the Costum Options'
        )] [PSObject] $CostumOptions
    )
    $get_all_unbound = get-Request -Session @Session -UriGetExtension "services_unbound.php"
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
    return $dictPostData
}

Function create-customoptions{
$custon_options = 'local-zone: "foo.bar" redirect
local-data: "foo.bar A 0.0.0.0" 
local-zone: "does.itwork" redirect
local-data: "does.itwork A 0.0.0.0"'
return $custon_options
}

Function main{
    Param
    (
        [Parameter(Mandatory=$true, Position=0,
        HelpMessage='The Server address'
        )] [PSObject] $Server,
        [Parameter(Mandatory=$true, Position=1,
        HelpMessage='The usernamen and password in a powershell object'
        )] [PSObject] $DefaulkCred,
        [Switch] $NoTest,
        [SWitch] $NoTLS
    )
if ($NoTLS) {
    if ($NoTest){}
    else{test-connection -Server $Server -NoTLS}
    $Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS
}
else{
    if ($NoTest){}
    else{test-connection -Server $Server}
    $Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred
}

$Custon_options = create-customoptions

$Postdata = create-dictdata -Session @Connection -CostumOptions $Custon_options
Post-request -Session @Connection -dictPostData $Postdata -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
$Postdata = @{
    "apply"="Apply Changes"
}
Post-request -Session @Connection -dictPostData $Postdata -UriGetExtension "services_unbound.php" -UriPostExtension "services_unbound.php"
}

$DefaulkCred  = New-Object System.Management.Automation.PSCredential ($Username, $(ConvertTo-SecureString -string $password -AsPlainText -Force))

if ($NoTLS) {
    if ($NoTest){main -Server $Server -DefaulkCred $DefaulkCred -NoTest -NoTLS}
    else{main -Server $Server -DefaulkCred $DefaulkCred -NoTLS}
}
else{
    if ($NoTest){main -Server $Server -DefaulkCred $DefaulkCred -NoTest}
    else{test-connection -Server $Server}
}