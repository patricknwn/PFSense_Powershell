The use of this script is "pfsense_api -server '' -username '' -Password '' -service '' -action '' arguments -NoTest -NoTLS'"<br/>
-NoTLS switch is used to set the connection protocol to http, default is https.<br/>
-NoTest switch is used to not test if the pfsense is online.<br/>
This script is tested on PFSense 2.4.4-RELEASE-p3<br/>
<br/>
the services suported are:<br/>
<br/>
Service						Help message<br/>
------------------------------------------------------------<br/>
Help:						Prints this text<br/>
<br/>
Route:						To mange static routes on the pfsense<br/>
Route Print:				Print all the static routes<br/>
Route Add:					Add a static route<br/>
Route Delete:				Delete a static route<br/>
<br/>
Interface:					To mange the interface's on the pfsense<br/>
Interface print:			Print the interface's<br/>
<br/>
Gateway:					To mange the Gateways on the pfsense<br/>
Gateway print:				Print the Gateways<br/>
Gateway add:				Add a Gateway<br/>
Gateway delete:				Delete a Gateway<br/>
Gateway default:            Set a Gateway as the default<br/>
<br/>
dnsresolver:				To mange the dnsresolver on the pfsense<br/>
dnsresolver print:			Print the dnsresolver<br/>
dnsresolver uploadcostum:	Upload a custom config to the dnsresolver<br/>
dnsresolver addhost:    	Add a host override<br/>
dnsresolver deletehost:    	Delete a host override<br/>
dnsresolver adddomain:    	Add a domain override<br/>
dnsresolver deletedomain:  	Delete a domain override<br/>
<br/>
Portfwd:                    To manage portforwarder on the pfsense<br/>
Portfwd Print:              Print the port forwarder rules<br/>
Portfwd Add:                Add a port forwarder rules<br/>
Portfwd Delete:             Delete a port forwarder rules<br/>
<br/>
Alias:                      To manage the aliases on the pfsense<br/>
Alias Print:                Print the aliases<br/>
Alias PrintSpecific:        Print the specific's of a alias<br/>
Alias Add:                  Add a new alias<br/>
Alias Delete:               Delete a alias<br/>
Alias Addvalue:             Add a value to a Alias<br/>
Alias Deletevalue:          Delete a value from a Alias<br/>
<br/>
Vip:                        To mange the Virtual IP's on the pfsense<br/>
Vip Print:                  Print the Virtual IP's<br/>
Vip Add:                    Add a Virtual IP's 'For now only IP Alias'<br/>
Vip Delete:                 Delete a Virtual IP
