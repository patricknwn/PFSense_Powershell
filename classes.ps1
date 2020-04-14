# classes to build:
<#
dhcpd
dhcpdv6
syslog
nat
filter = firewall
aliases
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

class PFFirewallRule {
    [bool]$IsFloating = $false
    [bool]$IsQuick = $false
    [bool]$IsDisabled = $false
    [bool]$IsLogged = $false
    [ValidateSet('pass', 'block', 'reject', '')]
        [string]$Type
    [ValidateSet('inet', 'inet6', 'inet46')]
    [string]$IPProtocol
    [PFInterface[]]$interface
    [ValidateSet('tcp', 'udp', 'tcp/udp', 'icmp', 'esp', 'ah', 'gre', 'ipv6', 
                 'igmp', 'pim', 'ospf', 'tp', 'carp', 'pfsync', '')]
        [string]$Protocol
    [string]$SourceType
    [string]$SourceAddress
    [string]$SourcePort
    [string]$DestType
    [string]$DestAddress
    [string]$DestPort
    [string]$Description

    
    static [string]$Section = "filter/rule"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        IsFloating = "floating"
        IsQuick = "quick"
        IsDisabled = "disabled"
        IsLogged = "log"
        Description = "descr"
        SourceType = "source/type"
        SourceAddress= "source/address"
        SourcePort = "source/port"
        DestType = "destination/type"
        DestAddress= "destination/address"
        DestPort = "destination/port"
    }
}

class PFFirewallSeparator {
    [string]$row
    [string]$text
    [string]$color
    [string]$interface

    static [string]$Section = "filter/separator"
    # property name as it appears in the XML, insofar it's different from the object's property name
    static $PropertyMapping = @{ 
        interface = "if"
    }
}

class PFGateway {
    [PFInterface]$Interface
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
    [string]$Name
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
        SourceType = "source"
        SourceAddress= "source"
        SourcePort = "source"
        DestType = "destination"
        DestAddress= "destination"
        DestPort = "destination"
        
    }
}

class PFServer {
    [string]$Address
    [pscredential]$Credential
    [bool]$NoTLS
    [bool]$SkipCertificateCheck = $false
    [XML]$XMLConfig
    [psobject]$Config = @{
        Interfaces = $null
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
    [PFInterface[]]$active_interface
    [PFInterface[]]$outgoing_interface
    [bool]$dnssec
    [bool]$enable
    [int]$port
    [int]$sslport
    [string[]]$hosts
    [string[]]$domainoverrides

    static [string]$Section = "unbound"
    static $PropertyMapping = @{ 
        active_interface = "active_interface"
        outgoing_interface = "outgoing_interface"
    }
}
