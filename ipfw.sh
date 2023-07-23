#!/bin/sh
# LICENSE: Apache 2.0   
# Copyright 2021-2023 Zhao Zhe, Alex Zhao    
#
# Firewall Configuration with author's respects to GFW from heart    
# GFW highly improved Network Engineer's competence
# Below Firewall based on IPv4
#
# Configurable Parameters
pif="ext0"                                     # Public Interface name used for internet
bif="bridge0"                                  # Bridge Private Network
dmzip="192.168.10.84"                          # DMZ IP address for internal network, a fixed host within home network 
int_subnet="192.168.10.0/24"                   # Configured internal subnet, home network IP range 
router_gw="192.168.10.1"                       # Router gateway
gateway="192.168.1.1"                          # Optical Modem gateway
satelite_ip="192.168.1.1"                      # Remote satelite IP address 
router_manage_client="192.168.10.0/24"         # Device which can access this Router from ssh/webbrowser

# Command Prefix
cmd="ipfw -q add"
ks="keep-state"

# Here $dmzip used as the DMZ - DNS cache server and auditor server
# DMZ zone is $int_subnet, please modify 192.168.*.0/24 if you want
ipfwd="fwd $dmzip ip from $int_subnet{2-254} to"

routeraddr=$(ifconfig $pif | grep 'inet' | cut -d: -f2 | awk '{print $2}')
echo "Current Router Main IP: $routeraddr"

# Used for outboud NAT rules, NAT rules start from 900
skip="skipto 05000"

# Bypass GFW, DMZ server bgfw, bgfw caused by main router is FreeBSD based, it requires extra forwarding
bgfw="$dmzip,1080"

##########################
#
# Flush all existed ipfw configurations
#
##########################
ipfw -q -f flush

ipfw disable one_pass
ipfw -q nat 10 config if $pif log

##########################
#
# ipfw table of only allowed IP from re
#
##########################
ipfw table routerpair destroy
ipfw table routerpair create type addr
ipfw table routerpair add $gateway
ipfw table routerpair add $routeraddr

##########################
#
# blocklist of ipfw
#
##########################
ipfw table blocklist destroy
ipfw table blocklist create type addr
ipfw table blocklist add 169.254.0.0/16

##########################
#
# Dynamic forwarding target which analysis from DNS query
# part of close loop firewall
#
##########################
ipfw table fwdlist destroy
ipfw table fwdlist create type addr

##########################
#
# Target blocklst of ipfw
# dynamic firewall to block some ip also analysised from DNS query
#
##########################
ipfw table tblocklist destroy
ipfw table tblocklist create type addr
# Class A private range of network
ipfw table tblocklist add 10.0.0.0/8
# Automatic configured IP not allowed
ipfw table tblocklist add 169.254.0.0/16

##########################
#
# lockdown list of ipfw
# lockdown device only let internal network accessible
#
##########################
ipfw table lockdownlist destroy
ipfw table lockdownlist create type addr


##########################
#
# DMZ allow access lit
# narrow down DMZ host access
#
##########################
ipfw table dmzallowlist destroy
ipfw table dmzallowlist create type addr
# Operator's home optical modem DNS, Default GW, other operator shall have similiar, but please check if it is 192.168.1.1
ipfw table dmzallowlist add $gateway
# From DMZ access Router
ipfw table dmzallowlist add $int_subnet

# From DMZ access remote proxy, below IP address used for bypass GFW
ipfw table dmzallowlist add $satelite_ip

########################## 
#
# NTP Servers for DMZ can access
#
##########################
ipfw table dmzallowlist add 202.118.1.130
ipfw table dmzallowlist add 116.203.151.74
ipfw table dmzallowlist add 84.16.73.33
ipfw table dmzallowlist add 139.199.215.251
ipfw table dmzallowlist add 84.16.67.12
ipfw table dmzallowlist add 202.118.1.81
ipfw table dmzallowlist add 193.182.111.143
ipfw table dmzallowlist add 119.28.183.184
ipfw table dmzallowlist add 202.112.29.82
ipfw table dmzallowlist add 119.28.206.193

##########################
#
# Main Router TrueNAS, FreeBSD egress control
#
##########################
ipfw table routeregresslist destroy
ipfw table routeregresslist create type addr

# NTP for Main Router
ipfw table routeregresslist add 193.182.111.143
ipfw table routeregresslist add 5.79.108.34
ipfw table routeregresslist add 202.118.1.81
ipfw table routeregresslist add 203.107.6.88
ipfw table routeregresslist add 162.159.200.1
ipfw table routeregresslist add 119.28.183.184
ipfw table routeregresslist add 84.16.73.33
ipfw table routeregresslist add 144.76.76.107
ipfw table routeregresslist add 130.61.44.4
ipfw table routeregresslist add 45.79.88.193
ipfw table routeregresslist add 204.93.207.11
ipfw table routeregresslist add 51.77.89.236

# TrueNAS
ipfw table routeregresslist add 192.41.228.0/24

# Internal Network
ipfw table routeregresslist add $int_subnet
ipfw table routeregresslist add $gateway

# Remote bridge below IP address used for bypass GFW
ipfw table routeregresslist add $satelite_ip

##########################
#
# smb and iscsi service allow list
#
##########################
ipfw table iscsi_allow_list destroy
ipfw table iscsi_allow_list create type addr
ipfw table samba_allow_list destroy
ipfw table samba_allow_list create type addr

##########################
#
# strict_hosts_list
# first level of filter to redirect wifi connected
# clients to per host defined target ip list based
# on DNS filter, DNS be redirect to cryptdns_proxy
# under this mode all network access not based on
# dns filter will be direct dropped
# 
##########################
ipfw table strict_hosts_list destroy
ipfw table strict_hosts_list create type addr valtype skipto

##########################
#
# NAT 10 table
#
##########################
$cmd 00001 nat 10 ip from any to any in via $pif

###################################################
#
# WAN defense at very beginning 
#
###################################################
$cmd 0030 deny log ip from any to any not antispoof in recv $pif
$cmd 0031 deny log all from any to any ipoptions lsrr,ssrr,rr,ts in recv $pif
$cmd 0032 abort log sctp from any to any via $pif
# Null scan
$cmd 0033 unreach net-prohib log tcp from any to any tcpflags !syn,!fin,!ack,!psh,!rst,!urg in recv $pif
# Xmas scan
$cmd 0034 unreach net-prohib log tcp from any to any tcpflags !syn,fin,!ack,psh,!rst,urg in recv $pif
$cmd 0035 unreach net-prohib log tcp from any to any tcpflags syn,fin,ack,psh,rst,urg in recv $pif
$cmd 0036 unreach6 admin-prohib log ip6 from any to any via $pif

###################################################
#
# Drop Main Router initiate Access to not controlled IP
# Home used firewall, no deny all at the end of the firewall rule, but with allow/block list mix used
# It shall be block all but with selected traffic come through
#
###################################################
$cmd 0037 deny ip from $routeraddr to not 'table(routeregresslist)' via $pif
$cmd 0038 deny ip from 192.168.1.1/24 to me in recv $pif

# Reject Broadcast from ext to int
$cmd 0039 deny ip from any to 255.255.255.255 in recv $pif

# Reject to join multicast through ext interface
$cmd 0040 deny ip from any to 224.0.0.251,224.0.0.252,239.255.255.250,239.255.255.253 out xmit $pif
$cmd 0041 deny ip from any to 224.0.0.1,224.0.0.2,224.0.1.22,224.0.1.35 out xmit $pif

# Reject ext interface connect to me in service port
$cmd 0042 deny tcp from any to me 443,80,22 in recv $pif
$cmd 0043 deny tcp from any to me 445,139,3260,6000 in recv $pif
$cmd 0044 deny tcp from any to me 6466,8388,1080,5357 in recv $pif
$cmd 0045 deny udp from any to 239.255.255.250 3702 in recv $pif
$cmd 0046 deny udp from any to me 21657 in recv $pif

###################################################
#
# Enable State based firewall
#
###################################################
$cmd 00090 check-state

###################################################
#
# Accept Rules Private Bridge Network
#
###################################################
# Antispoof of internal bridge network
# Lockdown DMZ to access remote which not existed in preconfigured "dmzallowlist"
$cmd 00093 deny ip from $dmzip to not 'table(dmzallowlist)' via $bif
# Lockdown configured device which internal network through bridge
$cmd 00094 deny ip from 'table(lockdownlist)' to not 192.168.0.0/16 via $bif
$cmd 00095 deny log ip from 'table(blocklist)' to any via $bif
$cmd 00096 deny log ip from any to any not antispoof in recv $bif

# Allow Internal Network to Access TrueNAS, log the events for recording/audit
$cmd 00099 accept log tcp from $router_manage_client to me 22,80,443 in via $bif setup $ks
$cmd 00100 deny tcp from any to me 22,80,443 in via $bif setup $ks

# Dynamic Firewall Configuration interface, log the events for recording/audit
$cmd 00111 accept log tcp from $dmzip to me 6466 in via $bif setup $ks

# And WebGUI's relevant service to internal network
$cmd 00120 accept tcp from me to me 6000 setup $ks

# Bhyve Service, DMZ runing as bhyve VM   
$cmd 00200 accept tcp from me to me 43673 setup $ks
$cmd 00210 accept tcp from me to me 42673 setup $ks
$cmd 00220 accept tcp from $router_manage_client to me 43673 in via $bif setup $ks
$cmd 00230 accept tcp from $router_manage_client to me 42673 in via $bif setup $ks

# DMZ allow ssh port from internal network
$cmd 00240 accept tcp from $int_subnet{2-254} to $dmzip 22 in via $bif setup $ks

# DHCP, DNS, TFTP, NTP Service, Critical
$cmd 00300 accept udp from any to me 67 in via $bif $ks
$cmd 00310 accept udp from any to me 69 in via $bif $ks

# Allow DHCP query from DMZ to gateway for local address fast resolution
$cmd 00315 $skip udp from $dmzip to $gateway 53 in recv $bif $ks

# Allow log service to audit on DMZ
$cmd 00318 allow tcp from $router_gw any to $dmzip 514 in via $bif setup $ks
$cmd 00319 allow udp from $router_gw any to $dmzip 514 in via $bif $ks

# This is used for only have DMZ as DNS server, reject every query to
# no matter router gw IP or direct public DNS server all reject
# for 84 has all query record audit function automatic enabled
$cmd 00320 reject udp from any to me 53 in recv $bif $ks
$cmd 00321 reject udp from $int_subnet to not $dmzip 53 in recv $bif $ks
$cmd 00322 reject udp from $int_subnet to 224.0.0.251 5353 in recv $bif $ks
$cmd 00330 reject tcp from any to me 53 in recv $bif setup $ks
$cmd 00331 reject tcp from $int_subnet to not $dmzip 53 in recv $bif setup $ks

# Provide NTP service to internal nework
$cmd 00340 accept udp from $int_subnet to me 123 in via $bif $ks

# Provide ICMP to internal network
$cmd 00350 accept icmp from $int_subnet to me in via $bif $ks

######################################################
#
# Allow Service For internal Nework to TrueNAS Server
#
######################################################
# SMB  this will extend for automatic security control
$cmd 00400 accept log tcp from $int_subnet{2-254} to me 445 in via $bif setup $ks
$cmd 00410 accept log tcp from $int_subnet{2-254} to me 139 in via $bif setup $ks

# iSCSI  this will extend for automatic security control
$cmd 00420 accept log tcp from $int_subnet{2-254} to me 3260 in via $bif setup $ks

# Shadowsocks for specific sock5 proxy
## socks5 accept from internal network 
$cmd 00430 accept log tcp from $int_subnet{2-254} to me 1080 in via $bif setup $ks
$cmd 00440 accept log udp from $int_subnet{2-254} to me 1080 in via $bif $ks

## accept ss-local to kcp tunnel 
$cmd 00450 accept tcp from me to me 8388 setup $ks

## accept ss-redir to kcp tunnel from DMZ, this caused by ss-redir only works on Linux it based on iptable/netfilter
$cmd 00460 accept tcp from $dmzip to me 8388 setup $ks

## accept traffic to access DMZ VM for Linux usage, VNC
$cmd 00461 accept tcp from $int_subnet{2-254} to $dmzip 5901 in via $bif setup $ks

## accept query DNS to DMZ VM from internal network
$cmd 00470 accept udp from $int_subnet to $dmzip 53 in recv $bif $ks 

##############################################
#
# Close Access to Main Router
#
##############################################
# Deny traffic from internal nework to router
$cmd 00471 deny udp from $int_subnet{2-254} to me in via $bif $ks
$cmd 00472 deny tcp from $int_subnet{2-254} to me in via $bif setup $ks

# Deny traffic to configured target IP list to outside of home network
$cmd 00475 deny ip from $int_subnet to 'table(tblocklist)' in via $bif

# strict hosts access control
$cmd 00476 skipto tablearg ip from 'table(strict_hosts_list)' to not $int_subnet in via $bif

# Rediect traffic from FreeBSD to DMZ VM, then DMZ VM to FreeBSD's kcptun
# Dynamic forwarding got from dns query analysis from DMZ VM
# This need to work with UmbrellaAgent/nfaudit and UmbrellaFirewall/dfirewall
$cmd 00502 $ipfwd 'table(fwdlist)' in via $bif $ks

######################################################
#
# Bootstrap, DHCP, DNS
# DHCP need no NAT, it only used to bootstrap $ext
#
######################################################
$cmd 02500 accept udp from me to any dst-port 67 out via $pif $ks

######################################################
#
# Outbound traffic bridge through private to internet
# Below is per protocol NAT allow list
#
######################################################
# DNS
$cmd 02510 $skip udp from any to any dst-port 53 out xmit $pif $ks
$cmd 02520 $skip tcp from any to any dst-port 53 out xmit $pif setup $ks

# ICMP
$cmd 02525 $skip icmp from any to any out via $pif $ks

# HTTP/HTTPS
$cmd 02530 $skip tcp from any to any dst-port 80 out via $pif setup $ks
$cmd 02540 $skip tcp from any to any dst-port 443 out via $pif setup $ks
$cmd 02541 $skip tcp from any to any dst-port 8080 out via $pif setup $ks

# EMAIL
$cmd 02550 $skip tcp from any to any dst-port 25 out via $pif setup $ks
$cmd 02560 $skip tcp from any to any dst-port 110 out via $pif setup $ks

# NTP
$cmd 02570 $skip udp from any to any dst-port 123 out via $pif $ks

# SSH
$cmd 02580 $skip tcp from any to any dst-port 22 out via $pif setup $ks

# FTP, may will be used
$cmd 02590 $skip tcp from any to any dst-port 20 out via $pif setup $ks
$cmd 02600 $skip tcp from any to any dst-port 21 out via $pif setup $ks

# XMPP 
$cmd 02610 $skip tcp from any to any dst-port 5223 out via $pif setup $ks

# MQTT
$cmd 02620 $skip tcp from any to any dst-port 1883 out via $pif setup $ks

# Try to allow internal traffic to outside from controlled subnet
$cmd 02900 $skip tcp from $int_subnet{2-254} to any out via $pif setup $ks
$cmd 02910 $skip udp from $int_subnet{2-254} to any out via $pif $ks

# Log not allowed outbound traffic
$cmd 02999 deny log ip from any to any out via $pif

######################################################
#
# Deny All Traffic for security control
#
######################################################
# Deny Netbios if possible
$cmd 03000 deny tcp from any to any dst-port 137 in via $pif 
$cmd 03001 deny udp from any to any dst-port 137 in via $pif
$cmd 03010 deny tcp from any to any dst-port 138 in via $pif
$cmd 03011 deny udp from any to any dst-port 138 in via $pif
$cmd 03020 deny tcp from any to any dst-port 139 in via $pif
$cmd 03030 deny tcp from any to any dst-port 81 in via $pif
$cmd 03031 deny tcp from any to any dst-port 113 in via $pif

# Deny All other access to TrueNAS Man interface
$cmd 03040 deny tcp from any to me dst-port 22,80,443 in via $pif 
$cmd 03060 deny tcp from any to me dst-port 6000 in via $pif

# Deny All not internal network to access TrueNAS
# SMB
$cmd 03070 deny tcp from any to me dst-port 445 in via $pif
$cmd 03080 deny tcp from any to me dst-port 139 in via $pif
# iSCSI
$cmd 03090 deny tcp from any to me dst-port 3260 in via $pif

# Deny All SSH connectivities both from public/private all deny
$cmd 03100 deny tcp from any to me 22 

# Block IPv6 totally, can extend 
$cmd 03200 deny ip6 from any to me6
$cmd 03210 deny ip6 from any to any

# Deny ICMP from public network
$cmd 03300 deny icmp from any to me

# Deny All Traffic through public intf 
$cmd 03400 deny all from any to any in via $pif

# Allow All Traffic through internal network 
$cmd 03999 accept ip from any to any

##########################################################
#
# strict host skipto set, configure from
# 4000 -> 4256 map 192.168.10.0 -> 192.168.10.256
#
# from strict host list skipto will direct to 4***
# rule target, with accept table t***
# be configured with DNS filter results
#
# specific rule will be added by dfirewall 
#
# 04000
# ...
# 04256
#
##########################################################

##########################################################
#
# NAT Configuration
#
##########################################################
$cmd 05000 nat 10 log ip from any to any out via $pif

# Opened firewall, you can modify it to deny all, author has a 
# single PCIe slot router without display card, low voltage CPU
# don't want to be locked out
$cmd 06000 accept ip from any to any 


