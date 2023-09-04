# UmbrellaFirewall

[English](README.md) | 简体中文    


# FreeBSD 防火墙 ipfw      
FreeBSD 操作系统 ipfw 防火墙配置工具可以阻止多种网络流量，动态的Umbrella Firewall根据网络流量需要通过DNS查询来     
解析实际访问的IP地址来对防火墙进行动态配置，解析内网所有设备DNS解析的工作由 Linux DMZ 服务器提供，幷由Umbreall Agent   
进行路由器上的防火墙更新。     

FreeBSD 路由器的配置     

修改 /etc/syslog.conf 已支持ipfw 防火墙日志        
```
security.*                                      @log.auditd.local    
```

log.auditd.local 需要静态配置到 /etc/hosts 来提供静态解析，syslog会更新日志到log.auditd.local所指定的服务器         
```
...   
192.168.10.?		log.auditd.local    
...   

```

修改 /etc/rc.conf 添加 FreeBSD 启动脚本           
```
# Enable Firewall for the NAS server
firewall_enable="YES"
firewall_script="/etc/ipfw.sh"
firewall_logging="YES"

gateway_enable="YES"
firewall_nat_enable="YES"
```

如果使用TrueNAS作为主路由器系统，那么需要修改 /conf/base/etc 和 /conf/base/etc/local     
来保证重启配置会更新到 /etc/ 和 /user/local/etc/

# Umbrella 动态防火墙是一个纵深网络防御的具体实现        
Umbrella防火墙是网络安全系统的第一道防线，默认从两个方向来控制网络安全访问     
    1. 从广域网到内网
    2. 从内网到广域网

Umbrella防火墙不光控制开放给外部访问的IP地址和端口，也控制通过Umbrella防火墙向外部访问的IP和端口    

# 如何自己搭建一套Umbreall防火墙系统        

    1. 一台PC系统，最好有多个磁盘组成的阵列    
    2. 按照说明书安装 FreeBSD/TrueNAS系统    
    3. 配置FreeBSD bhyve来运行Linux DMZ虚拟机    
    4. 安装UmbreallaFirewall工程的内容到FreeBSD系统作为主路由器系统    
    5. 将WiFi router配置为无线中继（非路由模式）   
    6. 通过交换机连接WiFi router到FreeBSD路由器     
 

基本网络拓扑结构     
```
  --------> Modem ----> MainRouter ----> Switch ----> WiFi router configured as wifi access point(disable router functions)    
                            ^    
                            |   
                            |
                      UmbrellaFirewall    



主路由器内部需要的网络组件         
                       
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


作者: Zhao Zhe (Alex)


![Donate](./DONATE.JPG)
![Donate](./DONATE_Z.JPG)
