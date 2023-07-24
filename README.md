# UmbrellaFirewall

CAUTION FreeBSD based not working on Linux   

This is a home used router which based on TrueNAS, TrueNAS is ZFS based NAS server which I'd like to use ZFS natively than direct on Linux    
Welcome to write the Linux Main Router firewall rules which can use ipset to replace FreeBSD's list   


# Firewall on TrueNAS(FreeBSD)   

ipfw based firewall configuration which will block many different types of traffic    
it based on the ideas that it only open the access when you really need it by lookup the domain name from internal network   
The open access agent is working DMZ(Linux) server


# This is a tool used for access network for technology and science only do not use it for bad things    



# Umbrella is a implementation approach of Defensh in Depth (DiD)   
UmbrellaFirewall is the frontline of the network security which block all by default from bidirectional:
	1. From WAN to LAN
	2. From LAN to WAN



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


Bhyve has limitation only works on X86 architecture currently.

         -------------------------------
        |                              |
        |  FreeBSD/TrueNAS             |
        |                              |
        |                              |
        |  Linux DMZ Bhyve on FreeBSD  |
        |                              |
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



Notes:
      UmbrellaFirewall works on FreeBSD/TrueNAS host
      UmbrellaAgent works on DMZ (Linux) which running by Bhyve (Qemu/KVM on FreeBSD)
      UmbrellaTelescope works on DMZ
      UmbrellaNightsWatch works on DMZ

```


Authro: Zhao Zhe(Alex)


![Donate](./DONATE.JPG)