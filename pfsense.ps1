$Server = '192.168.0.1'
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

###############
# First we need to connect to the pfsense.
###############

test-connection -Server $Server -NoTLS
$Connection = Connect-pfSense -Server $Server -Credentials $DefaulkCred -NoTLS 
#######
# All the dict's I have created to upload data to the pfsense
#######
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

# Sign the CSR
$request = Get-Request -Session @Connection -UriGetExtension "system_certmanager.php"
# We need the ID of the csr we just created
$ID = $($($($($request.parsedHtml.getElementsByTagName("div") | Where{ $_.className -eq "table-responsive" }).innerHTML -split "<TR>" | % {if($_ -match "CN=$($dictPostData.csr_dn_commonname.tostring())"){$_}}) -split "<A" | Select-String "href=")[0] -split ";")[1] -replace "[^0-9]" , ''
# And now we can get the CSR
$request = Get-Request -Session @Connection -UriGetExtension "system_certmanager.php?act=csr&id=$ID"
$CertsignReq = $request.ParsedHtml.getElementById("csr").innerHTML
#now we ask for the signed base64 code And Post the signed cert to the pfsense"The certificate signing request base64 is: `n`r{0} " -f $CertsignReq[string]$CertsignResp = Read-Host -Prompt "Please give thesignd entry"$dictPostData = @{
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

# extend Alias whith new data
# If you add a Host $dictToAdd looks like this @{Host="Descrition"}
# If you add a Port $dictToAdd looks like this @{Port="Descrition"}
# If you add a Network the $dictToAdd looks like @{Network="Subnet","Descrition"}
$dictToAdd = @{"192.168.2.0"="24","Test_one_two three"}
$get_alias = get-Request -Session @Connection -UriGetExtension "firewall_aliases.php?tab=all"
$all_alias = $($get_alias.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed sortable-theme-bootstrap") | %{$_.InnerText}).split([Environment]::NewLine)
ForEach ($line in $($all_alias[1..$all_alias.Length] | Where-Object {$_})){Write-host $Line}
#ToDo check if name exciste
$alias_name = Read-Host -Prompt "Please give name of the alias you would like to change"
$ID = $($($($get_alias.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed sortable-theme-bootstrap") | %{$_.innerHTML}).split([Environment]::NewLine) | select-string -pattern "$alias_name") -split ";")[0] -replace "[^0-9]" , ''
$alias_content_get = get-Request -Session @Connection -UriGetExtension "firewall_aliases_edit.php?id=$ID"
$($alias_content_get.ParsedHtml.getElementById("type")) | %{if($_.selected) {$type_value = $_.value()} }
$indexNumber = 0
$dictPostData = @{
    name = $($alias_content_get.ParsedHtml.getElementById("name")).value
    descr= $($alias_content_get.ParsedHtml.getElementById("descr")).value
    type = $type_value
    tab = $($alias_content_get.ParsedHtml.getElementById("tab")).value
    origname = $($alias_content_get.ParsedHtml.getElementById("origname")).value
    id = $($alias_content_get.ParsedHtml.getElementById("id")).value
    save="Save"}
if($type_value -eq "host"){
    while($True){
        if(-not $($alias_content_get.ParsedHtml.getElementById("detail$indexnumber")).value){break}
        foreach ($entry in "address$indexnumber","detail$indexnumber") {$dictPostData.Add("$entry",$($alias_content_get.ParsedHtml.getElementById("$entry")).value)}
        $indexNumber++
    }
    $dictToAdd.keys | % {
        $dictPostData.Add("address$indexnumber",$_)
        $dictPostData.Add("detail$indexnumber",$dictToAdd.Item($_))
        $indexNumber++    
    }
}
ElseIf($type_value -eq "network"){
    while($True){
        if(-not $($alias_content_get.ParsedHtml.getElementById("detail$indexnumber")).value){break}
        foreach ($entry in "address$indexnumber","detail$indexnumber") {$dictPostData.Add("$entry",$($alias_content_get.ParsedHtml.getElementById("$entry")).value)}
        $($alias_content_get.ParsedHtml.getElementById("address_subnet$indexnumber")) | %{if($_.selected) {$dictPostData.Add("address_subnet$indexnumber",$_.value())}}
        $indexNumber++
    }
    $dictToAdd.keys | % {
        $dictPostData.Add("address$indexnumber",$_)
        $dictPostData.Add("detail$indexnumber",$dictToAdd.Item($_)[1])
        $dictPostData.Add("address_subnet$indexnumber",$dictToAdd.Item($_)[0])
        $indexNumber++ 
    }  
}
ElseIf($type_value -eq "port"){
    while($True){
        if(-not $($alias_content_get.ParsedHtml.getElementById("detail$indexnumber")).value){break}
        foreach ($entry in "address$indexnumber","detail$indexnumber") {$dictPostData.Add("$entry",$($alias_content_get.ParsedHtml.getElementById("$entry")).value)}
        $indexNumber++
    }
    $dictToAdd.keys | % {
        $dictPostData.Add("address$indexnumber",$_)
        $dictPostData.Add("detail$indexnumber",$dictToAdd.Item($_))
        $indexNumber++    
    }
}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases_edit.php?id=$dictPostData.id" -UriPostExtension "firewall_aliases_edit.php?id=$dictPostData.id"
# Apply the changes
$dictPostData = @{
    apply="Apply+Changes"}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "firewall_aliases.php" -UriPostExtension "firewall_aliases.php"

# ToDo: Delete a Alias

# ToDo: Delete a entry from a alias


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

# ToDo: Delete a route

# Bind
# first we need to count the number of acl's that already excist:
$get_all_acl = get-Request -Session @Connection -UriGetExtension "pkg.php?xml=bind_acls.xml"
$all_acl_Div = $($get_all_acl.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed") | %{$_.InnerText}).split([Environment]::NewLine)
$indexNumber = 0
$all_acl_Div[1..$($all_acl_Div.Length-2)] | Where-Object {$_}| foreach {$indexNumber++}
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
$all_views_Div[1..$($all_views_Div.Length-2)] | Where-Object {$_}| foreach {$indexNumber++}
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

# Now we can add a zone:
# first we need the view to use:
$get_all_views = get-Request -Session @Connection -UriGetExtension "pkg.php?xml=bind_views.xml"
$all_views_Div = $($get_all_views.ParsedHtml.body.getElementsByClassName("table table-striped table-hover table-condensed") | %{$_.InnerText}).split([Environment]::NewLine)
ForEach ($line in $($all_views_Div[1..$($all_views_Div.Length - 2)] | Where-Object {$_})){Write-host $Line}
# ToDo: check if the name exists
$view_name = Read-Host -Prompt "Please give name of the view you would like to change"
# Count the amound of exicting views to set the ID field
$id = 0
$get_all_zones = get-Request -Session @Connection -UriGetExtension "pkg.php?xml=bind_zones.xml&id=0"
while($True){
        if(-not $($get_all_zones.ParsedHtml.getElementById("id_$ID")).className){break}
        $id++
    }
# And now we can create our post dict to add a zone
$dictPostData = @{
    name="local"
    description="to+resolve+.local"
    type="master"
    "view[]"="test"
    custom=""
    tll="3600"
    nameserver="root.local"
    ipns="192.168.0.1"
    mail=""
    serial=""
    refresh="1d"
    retry="2h"
    expire="4w"
    minimum="1h"
    "allowupdate[]"="none"
    "allowquery[]"="any"
    "allowtransfer[]"="any"
    hostname0="root"
    hosttype0="A"
    hostvalue0=""
    hostdst0="192.168.0.1"
    hostname1="ns"
    hosttype1="CNAME"
    hostvalue1=""
    hostdst1="root.local"
    customzonerecords=""
    xml="bind_zones.xml"
    id="$id"
    submit="Save"
}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "pkg_edit.php?xml=bind_zones.xml&id=$id" -UriPostExtension "pkg_edit.php?xml=bind_zones.xml&id=0"

# add entry's to a zone:
# For now only one record can be added
# Type can be: A, AAAA, DNAME, MX, CNAME, NS, LOC, SRV, PTR, TXT, SPF
$dictToAdd = @{
    hostname = "nu"
    hosttype ="A"
    hostdst = ""
    hostvalue = "123.234.212.1"}
$get_Zones = get-Request -Session @Connection -UriGetExtension "pkg.php?xml=bind_zones.xml"
# ToDo: only get the names from the line
$($($get_Zones.ParsedHtml.getElementById("mainarea").innerText).split([Environment]::NewLine) | Where-Object {$_}) | Select -Skip 1 | Select -SkipLast 1
$Zone_name = Read-Host -Prompt "Please give name of the Zone you would like to add a entry to"
$ID = $($($get_Zones.ParsedHtml.getElementById("mainarea").innerHTML -split "<TD" | select-string -pattern "class=listlr>$Zone_name ") -split ";")[2] -replace "[^0-9]" , ''
$Get_zone_information = get-Request -Session @Connection -UriGetExtension "pkg_edit.php?xml=bind_zones.xml&act=edit&id=$ID"

# Get the already filled in information:
$indexNumber = 0
$dictPostData = ""
$dictPostData = @{
    name=$($Get_zone_information.ParsedHtml.getElementById("name")).value
    description=$($Get_zone_information.ParsedHtml.getElementById("description")).value
    custom=""
    tll=$($Get_zone_information.ParsedHtml.getElementById("tll")).value
    nameserver=$($Get_zone_information.ParsedHtml.getElementById("nameserver")).value
    ipns=$($Get_zone_information.ParsedHtml.getElementById("ipns")).value
    mail=$($Get_zone_information.ParsedHtml.getElementById("mail")).value
    serial=$($Get_zone_information.ParsedHtml.getElementById("serial")).value
    refresh=$($Get_zone_information.ParsedHtml.getElementById("refresh")).value
    retry=$($Get_zone_information.ParsedHtml.getElementById("retry")).value
    expire=$($Get_zone_information.ParsedHtml.getElementById("expire")).value
    minimum=$($Get_zone_information.ParsedHtml.getElementById("minimum")).value
    customzonerecords=$($Get_zone_information.ParsedHtml.getElementById("customzonerecords")).value
    xml="bind_zones.xml"
    id=$($Get_zone_information.ParsedHtml.getElementById("id")).value
    submit="Save"
}
foreach ($entry in "view[]","allowupdate[]","allowquery","allowtransfer[]","type"){$($Get_zone_information.ParsedHtml.getElementById("$entry")) | %{if($_.selected) {$dictPostData.Add("$entry",$_.value())}}}
while($True){
    if(-not $($Get_zone_information.ParsedHtml.getElementById("hostname$indexnumber").value)){break}
    foreach ($entry in "hostname$indexNumber","hostvalue$indexNumber","hostdst$indexNumber","hosttype$indexNumber") {$dictPostData.Add("$entry",$($Get_zone_information.ParsedHtml.getElementById("$entry").value))}
    $indexNumber++
}
# add the data from the dictToAdd
$dictToAdd.keys | % { 
$dictPostData.Add("$_$indexnumber",$dictToAdd.Item($_))}
Post-request -Session @Connection -dictPostData $dictPostData -UriGetExtension "pkg_edit.php?xml=bind_zones.xml&id=$id" -UriPostExtension "pkg_edit.php?xml=bind_zones.xml&id=0"

