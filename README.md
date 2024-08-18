# UmbrellaFirewall

English | [简体中文](README-CN.md)    


# Firewall on TrueNAS(FreeBSD)   

ipfw based firewall configuration which will block many different types of traffic    
it based on the ideas that it only open the access when you really need it by lookup the domain name from internal network   
The open access agent is working DMZ(Linux) server    

Configuration on TrueNAS/FreeBSD    

Update /etc/syslog.conf    
```
security.*                                      @log.auditd.local    
```

log.auditd.local is the DMZ hostname configure its fixed IP address in /etc/hosts    
```
...   
192.168.10.?		log.auditd.local    
...   

```

Update /etc/rc.conf for FreeBSD initial script       
```
# Enable Firewall for the NAS server
firewall_enable="YES"
firewall_script="/etc/ipfw.sh"
firewall_logging="YES"

gateway_enable="YES"
firewall_nat_enable="YES"
```

If you use TrueNAS, it requires to modify /conf/base/etc  or  /conf/base/etc/local     
Above two folder remap to /etc/ and /usr/local/etc/    

# Umbrella is an implementation approach of Defense in Depth (DiD)    
UmbrellaFirewall is the frontline of the network security which block all by default from bidirectional:    
	1. From WAN to LAN   
	2. From LAN to WAN   

UmbreallaFirewall control traffic from public to internal with opened ports control and also with the capabilities
to control internal to public based on traffic monitoring


# How to build the similiar home router    

  PC install TrueNAS or FreeBSD OS and connect to optical modem or other modem provided by network operator       
  Configure the FreeBSD with bhyve, if you are not familiar with BSD, recommend to use TrueNAS    
 

```
Basic Connectivity    

  --------> Modem ----> MainRouter ----> Switch ----> WiFi router configured as wifi access point(disable router functions)    
                            ^    
                            |   
                            |
                      UmbrellaFirewall    



Within MainRouter     


Bhyve has limitation only works on X86 architecture currently, Linux DMZ can base on physical machine connected to the same internal network.     

                       
                     Modem   
                       ^
                       |
                       |
                       V
        --------------------------------
        |                              |
        |  FreeBSD/TrueNAS             |
        |   | firewall                 |
        |                              |
        |  Linux DMZ Bhyve on FreeBSD  |
        |   | agent                    |
        |   | telescope                |
        |   | nw                       |
        |                              |
        -------------------------------|
                       |
                       |
                       V
                    SWITCH  (home used no configuration required switch)
                       |
                       |----|------|------------|
                       V    V      V            V
                     WIFI  WIFI   ....        Nvidia(online analysis)
                                                | prophet


Notes:
      UmbrellaFirewall works on FreeBSD/TrueNAS host
      UmbrellaAgent works on DMZ (Linux) which running by Bhyve (Qemu/KVM on FreeBSD)
      UmbrellaTelescope works on DMZ
      UmbrellaNightsWatch works on DMZ

```


Authro: Zhao Zhe(Alex)
