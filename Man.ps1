$HelpMessageheader = "The use of this script is `"pfsense_api -server '' -username '' -Password '' -service '' -action '' argument1 argument2 argument3 argument4 argument5 -NoTest -NoTLS
-NoTLS switch is used to set the connection protocol to http, default is https.
-NoTest switch is used to not test if the pfsense is online.
This script is tested on PFSense 2.4.4-RELEASE-p3
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
$row.Action = ""
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
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Add network_addr/Subnet Gateway_name `"Description this must be between quotation marks`""
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Add 192.168.0.0/24 WAN_DHCP `"Description this must be between quotation marks`""
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = "Route"
$row.Action = "Delete"
$row.'Help message' = "Delete a static route"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Delete network_addr/Subnet(CIDR method) Gateway_name"
$manroute.Rows.Add($row)
$row = $manroute.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Route -action Delete 192.168.0.0/24 WAN_DHCP"
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
$row = $manGateway.NewRow()
$row.Service = "Gateway"
$row.Action = "Default"
$row.'Help message' = "set a Gateway as the default"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Gateway -action default Name 'to set the default gateway to Automatic enter Automatic, for None enter None'"
$manGateway.Rows.Add($row)
$row = $manGateway.NewRow()
$row.Service = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Gateway -action default new_gateway"
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
$row.Action = "Uploadcostum"
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
$row.Action = "PrintSpecific"
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
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add Network newNetwork_alias `"This is a network alias`" 192.168.0.0 24"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add Host newHost_alias `"This is a Host alias`" 192.168.0.1"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add Port newPort_alias `"This is a Port alias`" 443"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action add url newurl_alias `"This is a url alias`" url"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = "delete"
$row.'Help message' = "delete a aliase"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action delete name"
$row = $ManAlias.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action delete newurl_alias"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = "Addvalue"
$row.'Help message' = "add a value to a Alias"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action addvalue name `"Description this must be between quotation marks`" Address Subnet(CIDR method) 'Subnet is only necessary if you add to a network alias'"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action addvalue newNetwork_alias `"new value`" 192.168.1.0 24"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action addvalue newHost_alias `"new value`" 192.168.1.0"
$ManAlias.Rows.Add($row)
$row = $ManAlias.NewRow()
$row.Service = "Alias"
$row.Action = "Deletevalue"
$row.'Help message' = "delete a value from a Alias"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Alias -action deletevalue name Value Subnet(CIDR method) 'Subnet is only necessary if you add to a network alias'"
$ManAlias.Rows.Add($row)


$manvip = New-Object System.Data.DataTable
$manvip.Columns.Add("Service","string") | Out-Null
$manvip.Columns.Add("Action","string") | Out-Null
$manvip.Columns.Add("Help message","string") | Out-Null
$manvip.Columns.Add("Example","string") | Out-Null
$row = $manvip.NewRow()
$row.Service = "Vip"
$row.'Help message' = "to mange the Virtual IP's on the pfsense"
$row.Example = ""
$manvip.Rows.Add($row)
$row = $manvip.NewRow()
$row.Service = "Vip"
$row.Action = "Print"
$row.'Help message' = "print the Virtual IP's"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service VIP -action print"
$manvip.Rows.Add($row)
$row = $manvip.NewRow()
$row.Service = "Vip"
$row.Action = "Add"
$row.'Help message' = "add a Virtual IP's 'For now only IP Alias'"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service VIP -action add interface Address Subnet(CIDR method) `"Description this must be between quotation marks`" "
$manvip.Rows.Add($row)
$row = $manvip.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service VIP -action add WAN 192.168.0.2 24 `"This is a new VIP`" "
$manvip.Rows.Add($row)
$row = $manvip.NewRow()
$row.Service = "Vip"
$row.Action = "Delete"
$row.'Help message' = "Delete a Virtual IP"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service VIP -action delete Address"
$manvip.Rows.Add($row)
$row = $manvip.NewRow()
$row.Service = ""
$row.Action = ""
$row.'Help message' = ""
$row.Example = "pfsense_api -server '' -username '' -Password '' -service VIP -action delete 192.168.0.2 24"
$manvip.Rows.Add($row)


$ManFirewall = New-Object System.Data.DataTable
$ManFirewall.Columns.Add("Service","string") | Out-Null
$ManFirewall.Columns.Add("Action","string") | Out-Null
$ManFirewall.Columns.Add("Help message","string") | Out-Null
$ManFirewall.Columns.Add("Example","string") | Out-Null
$row = $ManFirewall.NewRow()
$row.Service = "Firewall"
$row.'Help message' = "to mange the Firewall on the pfsense"
$row.Action = ""
$row.Example = ""
$ManFirewall.Rows.Add($row)
$row = $ManFirewall.NewRow()
$row.Service = "Firewall"
$row.Action = "Print"
$row.'Help message' = "Print the firewall rules"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Firewall -action print"
$ManFirewall.Rows.Add($row)
$row = $ManFirewall.NewRow()
$row.Service = "Firewall"
$row.Action = "Print"
$row.'Help message' = "Print the firewall rules"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Firewall -action add top/bottom interface pass/drop/reject Protocol SourceType Source  `"If SourceType is network - Subnet`" 'SourcePort, if none `" `"' DestType Dest `"If DestType is network - Subnet`" DestPort `"Description this must be between quotation marks`" Log `"Yes if logging needs to be enabled`""
$ManFirewall.Rows.Add($row)
$row = $ManFirewall.NewRow()
$row.Service = "Firewall"
$row.Action = "Print"
$row.'Help message' = "Print the firewall rules"
$row.Example = "pfsense_api -server '' -username '' -Password '' -service Firewall -action add top wan pass tcp network 10.0.0.0 24 `" `" network 192.168.0.0 24 443 `"to allow traffic from 10.0.0.0/24 to 192.168.0.0/24 port 443`" Yes"
$ManFirewall.Rows.Add($row)









$manall = $man + $newline + $manroute + $newline + $manint + $newline + $manGateway + $newline + $mandnsresolver + $newline + $manportfwd + $newline + $ManAlias + $newline + $manvip + $newline + $ManFirewall + $newline