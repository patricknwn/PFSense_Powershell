# classes to build:
<#
dhcpd = Needs static mapping
dhcpdv6
syslog
load_balancer
openvpn
unbound = dnsresolver <= strange things happen here
cert = cerificates
#>

class PFAlias {
    [string]$Name
    [string]$Type
    [string[]]$Address
    [string]$Description
    [string[]]$Detail
 
    static [string]$Section = "aliases/alias"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Description = "descr"
    }
}

class PFdhcpd{
    [string[]]$interface
#    [PFinterface[]]$interface
    [string]$RangeFrom
    [string]$RangeTo
    [string]$netmask
    [string]$Domain
    [string]$Gateway
    [string]$DNSServer
    [string]$NTPServer    

    static [string]$Section = "dhcpd"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Interface = "name"
        RangeFrom = "range/from"
        RangeTo = "range/to"
        netmask = "netmask"
        Domain = "Domain"
        Gateway = "Gateway"
        DNSServer = "DNSServer"
        NTPServer = "NTPServer"
    }
}

class PFdhcpStaticMap{
    [string]$interface
#    [PFInterface[]]$Interface
    [string]$Hostname
    [string]$Domain
    [string]$ClientID
    [string]$MACaddr
    [string]$IPaddr
    [string]$Description
    [string]$Gateway
    [string]$DNSserver
    [string]$NTPServer

    static [string]$Section = "dhcpd/staticmap"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Interface = "../name"
        Hostname = "Hostname"
        Domain = "Domain"
        ClientID = "CID"
        IPaddr = "IPaddr"
        Description  = "descr"
        MACaddr  = "mac"
    }
}

class PFFirewallRule {
    [bool]$IsFloating = $false
    [bool]$IsQuick = $false
    [bool]$IsDisabled = $false
    [bool]$IsLogged = $false
    [ValidateSet('pass', 'block', 'reject', '')]
        [string]$Type
    [ValidateSet('inet', 'inet6', 'inet46')]
        [string]$IPProtocol
#    [PFInterface[]]$interface
    [string[]]$interface
    [ValidateSet('tcp', 'udp', 'tcp/udp', 'icmp', 'esp', 'ah', 'gre', 'ipv6', 
                 'igmp', 'pim', 'ospf', 'tp', 'carp', 'pfsync', '')]
        [string]$Protocol
#    [ValidateSet('network', 'address', 'any')]
    [hashtable]$Source
    [string]$SourceAddress
    [string]$SourcePort
    [hashtable]$Destination
    [string]$DestinationAddress
    [string]$DestinationPort
    [string]$Description

    static [string]$Section = "filter/rule"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        IsFloating = "floating"
        IsQuick = "quick"
        IsDisabled = "disabled"
        IsLogged = "log"
        Description = "descr"
        Source = "source" 
        SourceAddress= $null
        SourcePort = $null
        Destination = "destination"
        DestAddress= $null
        DestPort = $null
    }
}

class PFFirewallSeparator {
    [string]$row
    [string]$text
    [string]$color
    [PFInterface[]]$interface

    static [string]$Section = "filter/separator"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        interface = "if"
    }
}

class PFGateway {
#    [PFInterface[]]$interface
    [string]$Interface
    [string]$Gateway
    [string]$Monitor
    [string]$Name
    [string]$Weight
    [string]$IPProtocol
    [string]$Description

    static [string]$Section = "gateways/gateway_item"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Description = "descr"
    }
}

class PFInterface {
    [ValidateNotNullOrEmpty()][string]$Name
    [string]$Interface
    [string]$Description
    [string]$IPv4Address    # should be [ipaddress] object, but that's for later, is a native powershell object
    [string]$IPv4Subnet
    [string]$IPv4Gateway    # should be [PFGateway] object, but that's for later
    [string]$IPv6Address    # should be [ipaddress] object, but that's for later
    [string]$IPv6Subnet
    [string]$IPv6Gateway    # should be [PFGateway] object, but that's for later
    [string]$Trackv6Interface
    [string]$Trackv6PrefixId
    [bool]$BlockBogons
    [string]$Media
    [string]$MediaOpt
    [string]$DHCPv6DUID
    [string]$DHCPv6IAPDLEN

    static [string]$Section = "interfaces"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{
        Interface = "if"
        Description = "descr"
        IPv4Address = "ipaddr"
        IPv4Subnet = "subnet"
        IPv4Gateway = "gateway"
        IPv6Address = "ipaddrv6"
        IPv6Subnet = "subnetv6"
        IPv6Gateway = "gatewayv6"
        Trackv6Interface = "track6-interface"
        Trackv6PrefixId = "track6-prefix-id"
        DHCPv6DUID = "dhcp6-duid"
        DHCPv6IAPDLEN = "dhcp6-ia-pd-len"
    }

    [string] ToString(){
        return ([string]::IsNullOrWhiteSpace($this.Description)) ? $this.Name : $this.Description
    }
}

class PFNATRule {
    [string]$SourceType
    [string]$SourceAddress
    [string]$SourcePort
    [string]$DestType
    [string]$DestAddress
    [string]$DestPort
    [string]$protocol
    [string]$target
    [string]$LocalPort
    [string]$interface
    [string]$Description

    static [string]$Section = "nat/rule"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        LocalPort = "local-port"
        Description = "descr"
        SourceType = "source/keys"
        SourceAddress= "source/network" #ToDo: find a way for multiple options because address needs to be here as well
        SourcePort = "source/port"
        DestType = "destination/keys"
        DestAddress= "destination/network"
        DestPort = "destination/port"
        
    }
}

class PFServer {
    [string]$Address
    [pscredential]$Credential
    [bool]$NoTLS
    [bool]$SkipCertificateCheck = $false
    [System.Xml.XmlDocument]$XMLConfig     # XML-RPC answer when requesting the current configuration
    [psobject]$PSConfig # $this.XMLConfig parsed to powershell objects by the XmlRpc library
    [psobject]$PFConfig = @{  # holds the PF* objects 
        Interfaces = $null
        # TODO: need more objects defined here, so that this code is self-documenting and there are no magic keys created throughout the code
        # TODO: explore the idea of automagically creating all the keys from PSConfig as soon as we know them, i.e. in Get-PFConfiguration after the ConvertFrom-XML call
    }
    
    [string] ToString(){        
        $Schema = ($this.NoTLS) ? "http" : "https"
        return ("{0}://{1}/xmlrpc.php" -f $Schema, $this.Address)
    }
}

class PFStaticRoute {
    [string]$Network
    [string]$Gateway    # should be [PFGateway] object, but that's for later
    [string]$Description
    
    static [string]$Section = "staticroutes/route"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        Description = "descr"
    }
}

class PFUnbound {
    [string[]]$ActiveInterface
    [string[]]$OutgoingInterface
    #[PFInterface[]]$ActiveInterface
    #[PFInterface[]]$OutgoingInterface
    [bool]$dnssec
    [bool]$enable
    [int]$port
    [int]$sslport

    static [string]$Section = "unbound"
    static $PropertyMapping = @{
        ActiveInterface = "active_interface"
        OutgoingInterface = "outgoing_interface"
    }
}

class PFUnboundHost {
    [string]$Hostname
    [string]$Domain
    [string]$IPaddr
    [string[]]$AliasesHost
    [string[]]$AliasesDomain
    [string[]]$AliasesDescription

    static [string]$Section = "unbound/hosts"
    static $PropertyMapping = @{ 
        Hostname = "host"
        Domain = "Domain"
        IPaddr = "IP"
        aliasesHost = "aliases/item/host"
        AliasesDomain = "aliases/item/domain"
        AliasesDescription = "aliases/item/Description"
    }
}
