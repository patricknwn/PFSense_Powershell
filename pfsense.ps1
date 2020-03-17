﻿$Server = '192.168.0.1'
$Username = "admin"
$DefaultPass = ConvertTo-SecureString $(Read-Host -Prompt "Please give the default password of the pfsense template") -AsPlainText -Force
$DefaulkCred  = New-Object System.Management.Automation.PSCredential ($Username, $DefaultPass)
$assignedPassPlain = Read-Host -Prompt "Please give the password dedicated fot this pfsense"
$assignedPass = ConvertTo-SecureString $assignedPassPlain -AsPlainText -Force
$assignedCred = New-Object System.Management.Automation.PSCredential ($Username, $assignedPass)
$config = Get-Content ($(Read-Host -Prompt "Please give the full path of the config file"))
#$CA_name = Read-Host -Prompt "Please give the name of the CA"
#$CA_Data = Get-Content -Path $(Read-Host -Prompt "Please give the full path of file with the CA data")
$Project = "PFsense1"
$ID = "1" # The ID the CSR will get

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
            Write-Host $bodyLines
            $rawRet = Invoke-WebRequest -Uri $uri -Method Post -Body $bodyLines -WebSession $webSession -EA Stop -ContentType "multipart/form-data; boundary=$boundry" 
            Write-Host $rawRet
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
    return $rawRet
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

#######
# All the dict's I have created to upload data to the pfsense
#######

test-connection -Server $Server -NoTLS
$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS 

# Upload config to pfsense:
$LF = "`r`n" 
$configjoined = $config -join $LF
$Multiformdata = @{
    backuparea = ""
    nopackages = ""
    donotbackuprrd = "Yes"
    restorearea = ""
    encrypt_password = ""
    download = ""
    decrypt_password = ""
    conffile = "$configjoined"
    filename = "config.xml"
    restore = "Restore Configuration"
    }
$raw_Data = Post-request -Session @Connection -dictPostData $Multiformdata -UriGetExtension "diag_backup.php" -UriPostExtension "diag_backup.php" -Multiform
# after uploading the config, the pfsense reboots, we have to wait for this
test-connection -Server $Server -NoTLS -reboot
$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS


# create the dictionary to change the password and upload it
$dictPostData = @{
    usernamefld=$assignedCred.Username
    passwordfld1=$assignedPassPlain
    passwordfld2=$assignedPassPlain
    expires=""
    webguicss="pfSense.css"
    webguifixedmenu=""
    webguihostnamemenu=""
    dashboardcolumns="2"
    "groups[]"="admins"
    authorizedkeys=""
    ipsecpsk=""
    act=""
    userid="0"
    privid=""
    certid=""
    utype="system"
    oldusername="admin"
    save="Save"
    }
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_usermanager.php?act=edit&userid=0" -UriPostExtension "system_usermanager.php?act=edit&userid=0"

# Upload a new CA
$dictPostData=@{
    descr=$CA_name
    method="existing"
    cert=$CA_Data
    key=""
    serial=""
    save="Save"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_camanager.php?act=new" -UriPostExtension "system_camanager.php?act=new"

#create the dictionary to create the CSR
$dictPostData=@{
    method="external"
    descr="Test"
    csrtosign="new"
    csrpaste=""
    keypaste=""
    csrsign_lifetime="3650"
    csrsign_digest_alg="sha256"
    cert=""
    key=""
    csr_keylen="2048"
    csr_digest_alg="sha256"
    csr_dn_commonname="TestCN"
    csr_dn_country=""
    csr_dn_state=""
    csr_dn_city=""
    csr_dn_organization=""
    csr_dn_organizationalunit=""
    certref=""
    type="server"
    altname_type0="DNS"
    altname_value0="test.local"
    altname_type1="IP"
    altname_value1="192.168.0.1"
    save="Save"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_certmanager.php?act=new" -UriPostExtension "system_certmanager.php?act=edit"
$request = Get-Request -Session @Connection -UriGetExtension "system_certmanager.php?act=csr&id=$ID"
$CertsignReq = $request.ParsedHtml.getElementById("csr").innerHTML
#now we ask for the signed base64 code And Post the signed cert to the pfsense[string]$CertsignResp = Read-Host -Prompt "Please give thesignd entry"$dictPostData = @{
        descr=$Project
        csr=$CertsignReq
        cert=$CertsignResp
        id=$ID
        act="csr"
        save="Update"}   Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_certmanager.php?act=csr&id=$ID" -UriPostExtension "system_certmanager.php?act=csr"

# Add a Alias
$dictPostData = @{
    name="Name"
    descr="windows clients"
    type="network"
    address0="192.168.0.1"
    address_subnet0="23"
    detail0="this netwerk"
    tab="ip"
    origname=""
    save="Save"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?tab=ip" -UriPostExtension "firewall_aliases_edit.php?tab=ip"
# Apply the changes
$dictPostData = @{
    apply="Apply+Changes"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases.php?tab=ip" -UriPostExtension "firewall_aliases.php?tab=ip"

# Add Route
$dictPostData = @{
    network="192.168.210.0"
    network_subnet="24"
    gateway="WAN_DHCP"
    descr="this is a test route"
    save="Save"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_routes_edit.php" -UriPostExtension "system_routes_edit.php"
# Apply the changes
$dictPostData = @{
        apply="Apply+Changes"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "system_routes.php" -UriPostExtension "system_routes.php"

# Bind
# first we need to count the number of acl's that already excist:
$get_all_acl = get-Request -Session @Connection -UriGetExtension "pkg.php?xml=bind_acls.xml"
$all_acl_Div = $($get_all_acl.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed") | %{$_.InnerText}).split([Environment]::NewLine)
$indexNumber = 0
$all_acl_Div[1..$($all_acl_Div.Length-2)] | Where-Object {$_}| foreach {$indexNumber++; write-host $_}
$indexNumber
# and then use the indexnumber to upload a new one
$dictPostData = @{
    name="test1"
    description="gogogo1"
    value0="192.168.2.0/24"
    description0="test2"
    value1="192.168.3.0/23"
    description1="test3"
    xml="bind_acls.xml"
    id=$indexNumber
    submit="Save"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "pkg_edit.php?xml=bind_acls.xml&id=$indexNumber" -UriPostExtension "pkg_edit.php?xml=bind_acls.xml&id=$indexNumber"

# Then we need to add a view, here we have the same problem:
$get_all_views = get-Request -Session @Connection -UriGetExtension "pkg.php?xml=bind_views.xml"
$all_views_Div = $($get_all_views.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed") | %{$_.InnerText}).split([Environment]::NewLine)
$indexNumber = 0
$all_views_Div[1..$($all_views_Div.Length-2)] | Where-Object {$_}| foreach {$indexNumber++; write-host $_}
$indexNumber
$dictPostData = @{
    name="test"
    description="test"
    recursion="no"
    "match-clients`[`]"="any"
    "allow-recursion`[`]"="none"
    bind_custom_options=""
    xml="bind_views.xml"
    id=$indexNumber
    submit="Save"
    }
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "pkg_edit.php?xml=bind_views.xml&id=$indexNumber" -UriPostExtension "pkg_edit.php?xml=bind_views.xml&id=$indexNumber"

# Now we can add or edit a zone:
#first we need the view to use:
$indexNumber = 0
$get_all_views = get-Request -Session @Connection -UriGetExtension "pkg.php?xml=bind_views.xml"
$all_views_Div = $($get_all_views.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed") | %{$_.InnerText}).split([Environment]::NewLine)

$all_views_Div[1..$($all_views_Div.Length-2)] | Where-Object {$_} | foreach {
    'Line: {1} view Name {0}' -f $_,$indexNumber
    $indexNumber++
    }
$view_id = Read-Host -Prompt "Please give the line number of the alias you would like to change"
$all_views_Div[$view_id]