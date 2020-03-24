$HelpMessageheader = "The use of this script is `"pfsense_api -server '' -username '' -Password '' -service '' -action '' argument1 argument2 argument3 argument4 argument5 -NoTest -NoTLS'`"
the service`s suported are:"
$man = New-Object System.Data.DataTable
$man.Columns.Add("Service","string") | Out-Null
$man.Columns.Add("Action","string") | Out-Null
$man.Columns.Add("Help message","string") | Out-Null
$man.Columns.Add("Example","string") | Out-Null
$row = $man.NewRow()
$row.Service = "Help"
$row.'Help message' = "Prints this text"
$row.Example = ""
$man.Rows.Add($row)

$newline = New-Object System.Data.DataTable
$newline.Columns.Add("Service","string") | Out-Null
$newline.Columns.Add("Action","string") | Out-Null
$newline.Columns.Add("Help message","string") | Out-Null
$newline.Columns.Add("Example","string") | Out-Null
$row = $newline.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = ""
$newline.Rows.Add($row)

$manroute = New-Object System.Data.DataTable
$manroute.Columns.Add("Service","string") | Out-Null
$manroute.Columns.Add("Action","string") | Out-Null
$manroute.Columns.Add("Help message","string") | Out-Null
$manroute.Columns.Add("Example","string") | Out-Null
$row = $manroute.NewRow()
$row.Service = "Route"
$row.'Help message' = "to mange static route`s on the pfsense"
$row.Example = ""
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = "Route"
$row.Action = "Print"
$row.'Help message' = "Print all the static route`s"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action print"
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = "Route"
$row.Action = "Add"
$row.'Help message' = "Add a static route"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Add network_addr Subnet(CIDR method) Gateway_name `"Description this must be between quotation marks`""
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Add 192.168.0.0 24 WAN_DHCP `"Description this must be between quotation marks`""
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = "Route"
$row.Action = "Delete"
$row.'Help message' = "Delete a static route"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Delete network_addr Subnet(CIDR method) Gateway_name"
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Delete 192.168.0.0 24 WAN_DHCP"
$manroute.Rows.Add($row)

$manint = New-Object System.Data.DataTable
$manint.Columns.Add("Service","string") | Out-Null
$manint.Columns.Add("Action","string") | Out-Null
$manint.Columns.Add("Help message","string") | Out-Null
$manint.Columns.Add("Example","string") | Out-Null
$row = $manint.NewRow()
$row.Service = "Interface"
$row.'Help message' = "to mange the interface's on the pfsense"
$row.Example = ""
$manint.Rows.Add($row)
$row = $manint.NewRow()
$row.Service = "Interface"
$row.Action = "Print"
$row.'Help message' = "Print the interface's"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Interface -action print"
$manint.Rows.Add($row)

$manGateway = New-Object System.Data.DataTable
$manGateway.Columns.Add("Service","string") | Out-Null
$manGateway.Columns.Add("Action","string") | Out-Null
$manGateway.Columns.Add("Help message","string") | Out-Null
$manGateway.Columns.Add("Example","string") | Out-Null
$row = $manGateway.NewRow()
$row.Service = "Gateway"
$row.'Help message' = "to mange the Gateways on the pfsense"
$row.Example = ""
$manGateway.Rows.Add($row)
$row = $manGateway.NewRow()
$row.Service = "Gateway"
$row.Action = "Print"
$row.'Help message' = "Print the Gateways"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Gateway -action print"
$manGateway.Rows.Add($row)
$row = $manGateway.NewRow()
$row.Service = "Gateway"
$row.Action = "Add"
$row.'Help message' = "add a Gateway"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Gateway -action add Name GW_address Monito_addr interface `"Description this must be between quotation marks`""
$manGateway.Rows.Add($row)
$row = $manGateway.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Gateway -action add new_gateway 192.168.0.2 192.168.0.2 WAN `"Description this must be between quotation marks`""
$manGateway.Rows.Add($row)
$row = $manGateway.NewRow()
$row.Service = "Gateway"
$row.Action = "Delete"
$row.'Help message' = "delete a Gateway"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Gateway -action delete Name"
$manGateway.Rows.Add($row)
$row = $manGateway.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Gateway -action delete new_gateway"
$manGateway.Rows.Add($row)

$mandnsresolver = New-Object System.Data.DataTable
$mandnsresolver.Columns.Add("Service","string") | Out-Null
$mandnsresolver.Columns.Add("Action","string") | Out-Null
$mandnsresolver.Columns.Add("Help message","string") | Out-Null
$mandnsresolver.Columns.Add("Example","string") | Out-Null
$row = $mandnsresolver.NewRow()
$row.Service = "Dnsresolver"
$row.'Help message' = "to mange the dnsresolver on the pfsense"
$row.Example = ""
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = "Dnsresolver"
$row.Action = "Print"
$row.'Help message' = "print the dnsresolver"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action print"
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = "Dnsresolver"
$row.Action = "Uplouadcostum"
$row.'Help message' = "upload a custom config to the dnsresolver"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action UploadCustom `"Custom File`""
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action UploadCustom CustomOptions.txt"
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = "Dnsresolver"
$row.Action = "AddHost"
$row.'Help message' = "add a host override"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action addhost host domain ipaddress `"Description this must be between quotation marks`""
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action addhost localhost localdomain 192.168.0.2 `"this is a test host`""
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = "Dnsresolver"
$row.Action = "Deletehost"
$row.'Help message' = "delete a host override"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action deletehost host domain"
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action deletehost localhost localdomain"
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = "Dnsresolver"
$row.Action = "AddDomain"
$row.'Help message' = "add a domain override"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action adddomain domain ipaddress `"Description this must be between quotation marks`""
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action adddomain localdomain 192.168.0.2 `"this is a test host`""
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = "Dnsresolver"
$row.Action = "DeleteDomain"
$row.'Help message' = "delete a host override"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action deletedomain domain ipaddress"
$mandnsresolver.Rows.Add($row)
$row = $mandnsresolver.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service dnsresolver -action deletedomain localdomain 192.168.0.2"
$mandnsresolver.Rows.Add($row)


$manportfwd = New-Object System.Data.DataTable
$manportfwd.Columns.Add("Service","string") | Out-Null
$manportfwd.Columns.Add("Action","string") | Out-Null
$manportfwd.Columns.Add("Help message","string") | Out-Null
$manportfwd.Columns.Add("Example","string") | Out-Null
$row = $manportfwd.NewRow()
$row.Service = "portfwd"
$row.'Help message' = "To manage portforwarder on the pfsense"
$row.Example = ""
$manportfwd.Rows.Add($row)
$row = $manportfwd.NewRow()
$row.Service = "Portfwd"
$row.Action = "Print"
$row.'Help message' = "print the port forwarder rules"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service portfwd -action print"
$manportfwd.Rows.Add($row)
$row = $manportfwd.NewRow()
$row.Service = "Portfwd"
$row.Action = "Add"
$row.'Help message' = "add a port forwarder rules"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service portfwd -action add Interface Protocol Dest_Address Dest_Ports NAT_IP NAT_Ports `"Description this must be between quotation marks`""
$manportfwd.Rows.Add($row)
$row = $manportfwd.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service portfwd -action add LAN TCP 192.168.0.2 8443 10.0.0.1 443 `"Description this must be between quotation marks`""
$manportfwd.Rows.Add($row)
$row = $manportfwd.NewRow()
$row.Service = "Portfwd"
$row.Action = "Delete"
$row.'Help message' = "delete a port forwarder rule"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service portfwd -action delete Dest_Address Dest_Ports NAT_IP NAT_Ports"
$manportfwd.Rows.Add($row)
$row = $manportfwd.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service portfwd -action delete 192.168.0.2 8443 10.0.0.1 443"
$manportfwd.Rows.Add($row)

$ManAlias = New-Object System.Data.DataTable
$ManAlias.Columns.Add("Service","string") | Out-Null
$ManAlias.Columns.Add("Action","string") | Out-Null
$ManAlias.Columns.Add("Help message","string") | Out-Null
$ManAlias.Columns.Add("Example","string") | Out-Null
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = ""
$row.'Help message' = "To manage aliases on the pfsense"
$row.Example = ""
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = "Print"
$row.'Help message' = "Print the aliases"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action print"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = "SpecificPrint"
$row.'Help message' = "Print a specific aliase"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action SpecificPrint name"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = "Add"
$row.'Help message' = "Add a new aliases"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add Type Name `"Description this must be between quotation marks`" Address Subnet(CIDR method)"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add Network newNetwork_alias `"This is a network alias`" 192.168.0.0 24"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add Host newHost_alias `"This is a Host alias`" 192.168.0.1"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add Port newPort_alias `"This is a Port alias`" 443"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add url newurl_alias `"This is a url alias`" url"
$ManAlias.Rows.Add($row)





$manall = $man + $newline + $manroute + $newline + $manint + $newline + $manGateway + $newline + $mandnsresolver + $newline + $manportfwd + $newline + $ManAlias + $newline