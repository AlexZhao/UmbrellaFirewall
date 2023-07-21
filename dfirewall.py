#!/usr/bin/python
# LICENSE: Apache 2.0
# Copyright 2021-2023 Zhao Zhe, Alex Zhao
# Python Script direct call ipfw to update two types of access
# device with DHCPed IP address
# target IP/Port according to blocked list IPs
# totally based on ipfw for bidirectional access control
# flask as the restful API endpint received request from DMZ VM
# home use 192.168.10.84 - > 192.168.10.1
# with totally controlled port and record
# DMZ will analysis traffic and push firewall update to router
# e.g.
#        put not refresh lease device to quarantine
#        dynamic access target blocking
#
# Basic ipfw update for source based IP filter out
#   ipfw table blocklist add IP
#   ipfw table blocklist delete IP
#
# Lockdown mode for specific source device
#   ipfw table lockdownlist add IP
#   ipfw table lockdownlist delete IP
# Lockdown mode will disable all access to external network but can be proxied
# through shadowsocks proxy, dynamic firewall can base on this tech to gradulally
# open traffic/close traffic to measure defined device behavior with telescope
# to locate unknow threats
#
# TODO:
# Basic Target Block list
#   ipfw table tblocklist add IP
#   ipfw table tblocklist delete IP
#
# Allow list for iscsi/samba access control, get rid of password trying
#   ipfw table iscsi_allow_list
#   ipfw table samba_allow_list
# 
# Forward list according to DNS configuration and analysis results
#   regex match in Fedora Bunker for domain name direct bypass GFW
#   ipfw table fwdlist
# port = 6466, hex df dynamic firewall
# Request
#   {
#       cmd: blocklist_add
#       ip: [192.168.10.55]
#   }
#
#   {
#       cmd: blocklist_del
#       ip: []
#   }
#
# Response
#   {
#       status: success/unsuccess
#   }
#
# Add Simple share secrect for security control token
# e.g. Token: a long data share across router and client
# Basic security
#
import os;
import json;
import subprocess;
import re;

from base64 import b64encode

from flask import Flask
from flask_restful import reqparse, abort, Resource, Api

g_dummy_test = False

app = Flask(__name__)
api = Api(app)

# IPFWIntf direct opeate on ipfw firewall command
class IPFWIntf:
    def __init__(self):
        """
        IPFW intf initialization
        """
        self.ip_addr_filter = re.compile("(\d+\.\d+\.\d+\.\d+\/\d+)", re.IGNORECASE)

    def list_src_ip(self):
        """
        return a list of source IP addresses
        """
        command = "ipfw table blocklist list"
        if g_dummy_test:
            print("Request to list all src ip within blocklist")
        else:
            ip_list = subprocess.Popen(['ipfw','table blocklist list'], stdout=subprocess.PIPE)
            jsonobj = {"result": "success", "ip_list": []}
            for line in ip_list.stdout.readlines():
                ip_addr_str = line.decode("utf-8")
                ip_addr_match = self.ip_addr_filter.match(ip_addr_str)
                if ip_addr_match:
                    if ip_addr_match.group(1):
                        ip_addr = ip_addr_match.group(1)
                        print("source of line data   ", ip_addr)
                        jsonobj["ip_list"].append(ip_addr)
            return jsonobj

    def block_src_ip(self, src_ip_addr):
        """
        block src ip to blocklist table
        """
        command = "ipfw table blocklist add {ip_addr}".format(ip_addr=src_ip_addr)
        if g_dummy_test:
            print("Request to block source IP addr ", src_ip_addr, " command = ", command)
        else:
            status = os.system(command)
            if status == 0:
                return {"result": "success"}
            else:
                return {"result": "failed"}

    def unblock_src_ip(self, src_ip_addr):
        """
        Unblock src ip from blocklist table
        """
        command = "ipfw table blocklist delete {ip_addr}".format(ip_addr=src_ip_addr)
        if g_dummy_test:
            print("Request to unblock source IP addr ", src_ip_addr, " command ", command)
        else:
            status = os.system(command)
            if status == 0:
                return {"result": "success"}
            else:
                return {"result": "failed"}

    def list_target_ip(self):
        """
        list target ip from tblocklist
        """
        command = "ipfw table tblocklist list"
        if g_dummy_test:
            print("List all blocked target IPs")
        else:
            ip_list = subprocess.Popen(['ipfw','table tblocklist list'], stdout=subprocess.PIPE)
            jsonobj = {"result": "success", "ip_list": []}
            for line in ip_list.stdout.readlines():
                ip_addr_str = line.decode("utf-8")
                ip_addr_match = self.ip_addr_filter.match(ip_addr_str)
                if ip_addr_match:
                    if ip_addr_match.group(1):
                        ip_addr = ip_addr_match.group(1)
                        print("source of line data   ", ip_addr)
                        jsonobj["ip_list"].append(ip_addr)
            return jsonobj

    def block_target_ip(self, tgt_ip_addr):
        """
        block target ip to tblocklist table
        """
        command = "ipfw table tblocklist add {ip_addr}".format(ip_addr=tgt_ip_addr)
        if g_dummy_test:
            print("Request to block target IP addr ", tgt_ip_addr, " command = ", command)
        else:
            status = os.system(command)
            if status == 0:
                return {"result": "success"}
            else:
                return {"result": "failed"}

    def unblock_target_ip(self, tgt_ip_addr):
        """
        Unblock target ip from tblocklist table
        """
        command = "ipfw table tblocklist delete {ip_addr}".format(ip_addr=tgt_ip_addr)
        if g_dummy_test:
            print("Request to unblock target IP addr ", tgt_ip_addr, " command = ", command)
        else:
            status = os.system(command)
            if status == 0:
                return {"result": "success"}
            else:
                return {"result": "failed"}

    def add_ip_to_skipto_tbl(self, ip_addr, tbl):
        """
        Add client IP to skipto table
        """
        idx = ip_addr.rsplit('.')[3]

        skipto = "04{num}".format(num=idx.zfill(3))
        command = "ipfw table {table} add {ip_addr} {skipto}".format(table=tbl, ip_addr=ip_addr, skipto=skipto)
        if g_dummy_test:
            print("Request to add IP ", ip_addr, " to table ", tbl, " command = ", command)
        else:
            status = os.system(command)
        
        target_table = "t{num}".format(num=idx.zfill(3))

        clean_tbl_command = "ipfw table {table} destroy".format(table=target_table)
        os.system(clean_tbl_command)

        add_tbl_command = "ipfw table {table} create type addr".format(table=target_table)
        if g_dummy_test:
            print("create target filter table ", ip_addr, " command ", add_tbl_command)
        else:
            status = os.system(add_tbl_command)
        
        print(add_tbl_command)

        rule_num = "04{num}".format(num=idx.zfill(3))
        delete_if_existed = "ipfw delete {rule_num}".format(rule_num=rule_num)
        os.system(delete_if_existed)

        print("delete if existed  ", delete_if_existed)

        update_forward_command = "ipfw add {rule_num} skipto 502 ip from {ip_addr} to 'table({table})' via bridge0".format(rule_num=rule_num, ip_addr=ip_addr, table=target_table)
        if g_dummy_test:
            print("Add target table filter for ", target_table, " failed")
        else:
            status = os.system(update_forward_command)

        print("forward  ", update_forward_command)

        drop_packet = "ipfw add {rule_num} deny ip from {ip_addr} to not 'table({table})' via bridge0".format(rule_num=rule_num, ip_addr=ip_addr, table=target_table)
        if g_dummy_test:
            print("Add packet drop rule ", drop_packet)
        else:
            status = os.system(drop_packet)

        print(update_forward_command)

        return {"result": "success"}

    def del_ip_from_skipto_tbl(self, ip_addr, tbl):
        """
        Del client IP from skipto table
        """
        cmd_res = "success"
        idx = ip_addr.rsplit('.')[3]

        target_table = "t{num}".format(num=idx.zfill(3))
        rule_num = "04{num}".format(num=idx.zfill(3))
        del_fwd_rule_cmd = "ipfw delete {rule_num}".format(rule_num=rule_num)
        status = os.system(del_fwd_rule_cmd)
        if status != 0:
            cmd_res = "failed"
        
        del_t_tbl_cmd = "ipfw table {table} destroy".format(table=target_table)
        status = os.system(del_t_tbl_cmd)
        if status != 0:
            cmd_res = "failed"
        
        del_ip_from_tbl_cmd = "ipfw table {table} del {ip_addr}".format(table=tbl, ip_addr=ip_addr)
        status = os.system(del_ip_from_tbl_cmd)
        if status != 0:
            cmd_res = "failed"
        
        return {"result": cmd_res}

    def list_ip_from_skipto_tbl(self, tbl):
        """
        List all IPs from skipto table
        """
        if g_dummy_test:
            print("Reuqest to list IP from skipto table ", tbl)
        else:
            cmdline = "table {table} list".format(table=tbl)
            ip_list = subprocess.Popen(['ipfw', cmdline], stdout=subprocess.PIPE)
            jsonobj = {"result": "success", "ip_list": []}
            for line in ip_list.stdout.readlines():
                ip_addr_str = line.decode("utf-8")
                jsonobj["ip_list"].append(ip_addr_str)
            return jsonobj

    def add_ip_to_tbl(self, ip_addr, tbl):
        """
        Add new IP address to the tbl indicated table
        """
        command = "ipfw table {table} add {ip_addr}".format(table=tbl, ip_addr=ip_addr)
        if g_dummy_test:
            print("Request to add IP ", ip_addr, " to predefined table ", tbl, " command = ", command)
        else:
            status = os.system(command)
            if status == 0:
                return {"result": "success"}
            else:
                return {"result": "failed"}

    def del_ip_from_tbl(self, ip_addr, tbl):
        """
        Del IP address from tbl indicated table
        """
        command = "ipfw table {table} delete {ip_addr}".format(table=tbl, ip_addr=ip_addr)
        if g_dummy_test:
            print("Request to delete IP ", ip_addr, " from predefined table ", tbl, " command = ", command)
        else:
            status = os.system(command)
            if status == 0:
                return {"result": "success"}
            else:
                return {"result": "failed"}
    
    def list_ip_from_tbl(self, tbl):
        """
        List all IP address within tbl
        """
        if g_dummy_test:
            print("Reuqest to list IP from table ", tbl)
        else:
            cmdline = "table {table} list".format(table=tbl)
            ip_list = subprocess.Popen(['ipfw', cmdline], stdout=subprocess.PIPE)
            jsonobj = {"result": "success", "ip_list": []}
            for line in ip_list.stdout.readlines():
                ip_addr_str = line.decode("utf-8")
                ip_addr_match = self.ip_addr_filter.match(ip_addr_str)
                if ip_addr_match:
                    if ip_addr_match.group(1):
                        ip_addr = ip_addr_match.group(1)
                        print("source of line data   ", ip_addr)
                        jsonobj["ip_list"].append(ip_addr)
            return jsonobj

    def flush_tbl(self, tbl):
        """
        Flush Table 
        """
        command = "ipfw table {table} flush".format(table=tbl)
        if g_dummy_test:
            print("Request to flush table ", tbl)
        else:
            status = os.system(command)
            if status == 0:
                return {"result": "success"}
            else:
                return {"result": "failed"}

g_ipfw_intf = IPFWIntf()

parser = reqparse.RequestParser()
parser.add_argument('ip_addr')
parser.add_argument('mon_addr')

class MainPage(Resource):
    def get(self):
        return {'dynamic_firewall': 'IPFW dynamic firewall'}

class ListBlockSrcIP(Resource):
    def get(self):
        """
        List all IP address in blocklist
        """
        result_obj = g_ipfw_intf.list_src_ip()
        return {'list_blocked_src_ip': result_obj}

class AddBlockSrcIP(Resource):
    def get(self):
        return {'usage': "POST to add blocked IP addr"}
    def post(self):
        """
        Post add block src IP
        """
        src_ip_addr = parser.parse_args()['ip_addr']
        if src_ip_addr:
            return g_ipfw_intf.block_src_ip(src_ip_addr)
        else:
            return {"add_block_src_ip": "malformed request"}

class DelBlockSrcIP(Resource):
    def get(self):
        return {'usage': "POST to delete blocked IP addr"}
    def post(self):
        """
        Post del block src IP
        """
        src_ip_addr = parser.parse_args()['ip_addr']
        if src_ip_addr:
            return g_ipfw_intf.unblock_src_ip(src_ip_addr)
        else:
            return {"del_block_src_ip": "malformed request"}

class AddBlockSrcMAC(Resource):
    def get(self):
        return {'usage': "POST to add blocked src MAC addr"}
    def post(self):
        """
        Post add block src MAC
        """

class DelBlockSrcMAC(Resource):
    def get(self):
        return {'usage': "POST to del blocked src MAC addr"}
    def post(self):
        """
        Post del block src MAC
        """

class ListBlockTargetIP(Resource):
    def get(self):
        """
        List all target IPs in blocktgtip
        """
        result_obj = g_ipfw_intf.list_target_ip()
        return {'list_blocked_src_ip': result_obj}


class AddBlockTargetIP(Resource):
    def get(self):
        return {'usage': "POST to add block target IP addr"}
    def post(self):
        """
        Post add block target IP
        """
        tgt_ip_addr = parser.parse_args()['ip_addr']
        if tgt_ip_addr:
            return g_ipfw_intf.block_target_ip(tgt_ip_addr)
        else:
            return {"add_block_target_ip": "malformed request"}

class DelBlockTargetIP(Resource):
    def get(self):
        return {'usage': "POST to del block target IP addr"}
    def post(self):
        """
        Post del block target IP
        """
        tgt_ip_addr = parser.parse_args()['ip_addr']
        if tgt_ip_addr:
            return g_ipfw_intf.unblock_target_ip(tgt_ip_addr)
        else:
            return {"del_block_target_ip": "malformed request"}

class AddFwdTargetIp(Resource):
    def get(self):
        return {'usage': "POST to add forward target IP addr"}
    def post(self):
        """
        Post add forward target IP
        """
        fwd_tgt_ip_addr = parser.parse_args()['ip_addr']
        if fwd_tgt_ip_addr:
            return g_ipfw_intf.add_ip_to_tbl(fwd_tgt_ip_addr, "fwdlist")
        else:
            return {"add_fwd_target_ip": "malformed request"}

class DelFwdTargetIp(Resource):
    def get(self):
        return {'usage': "POST to del forward target IP addr"}
    def post(self):
        """
        Post del forward target IP
        """
        fwd_tgt_ip_addr = parser.parse_args()['ip_addr']
        if fwd_tgt_ip_addr:
            return g_ipfw_intf.del_ip_from_tbl(fwd_tgt_ip_addr, "fwdlist")
        else:
            return {"del_fwd_target_ip": "malformed request"}

class ClrFwdTargetIp(Resource):
    def get(self):
        return {'usage': "POST to clr forward target IP table fwdlist"}
    def post(self):
        """
        Post clr forward target IPs within table fwdlist
        """
        fwd_tgt_table = parser.parse_args()['table']
        if fwd_tgt_table:
            if fwd_tgt_table == "fwdlist":
                return g_ipfw_intf.flush_tbl(fwd_tgt_table)
            else:
                return {'clr_fwd_target_ip': "wrong table provided"}
        else:
            return {'clr_fwd_target_ip': "malformed request"}

class ListLockDownIP(Resource):
    def get(self):
        result_obj = g_ipfw_intf.list_ip_from_tbl("lockdownlist")
        return {'list_lockdown_dev_ip': result_obj}

class AddLockDownIP(Resource):
    def get(self):
        return {'usage': "POST to add lockdown device IP addr"}
    def post(self):
        """
        POST add lockdown device IP
        """
        lockdown_dev_ip_addr = parser.parse_args()['ip_addr']
        if lockdown_dev_ip_addr:
            return g_ipfw_intf.add_ip_to_tbl(lockdown_dev_ip_addr, "lockdownlist")
        else:
            return {"add_lockdown_dev_ip": "malformed request"}

class DelLockDownIP(Resource):
    def get(self):
        return {'usage': "POST to del lockdown device IP addr"}
    def post(self):
        """
        POST delete lockdown device IP
        """
        lockdown_dev_ip_addr = parser.parse_args()['ip_addr']
        if lockdown_dev_ip_addr:
            return g_ipfw_intf.del_ip_from_tbl(lockdown_dev_ip_addr, "lockdownlist")
        else:
            return {'del_lockdown_dev_ip': "malformed request"}

# Below Code write most part by Copilot with human fix
# Copilot not corrected process the block compared to allow list 
class DMZAllowTargetIP(Resource):
    """
    DMZ Automatic add target IP address from dns lookup
    """
    def get(self):
        return {'usage': "POST to add DMZ target IP addr"}
    def post(self):
        """
        Post add DMZ target IP
        """
        dmz_tgt_ip_addr = parser.parse_args()['ip_addr']
        if dmz_tgt_ip_addr:
            return g_ipfw_intf.add_ip_to_tbl(dmz_tgt_ip_addr, "dmzallowlist")
        else:
            return {"add_dmz_target_ip": "malformed request"}

class DMZBlockTargetIP(Resource):
    """
    DMZ Automatic remove target IP address from dns lookup
    """
    def get(self):
        return {'usage': "POST to remove DMZ target IP addr"}
    def post(self):
        """
        Post remove DMZ target IP
        """
        dmz_tgt_ip_addr = parser.parse_args()['ip_addr']
        if dmz_tgt_ip_addr:
            return g_ipfw_intf.del_ip_from_tbl(dmz_tgt_ip_addr, "dmzallowlist")
        else:
            return {"del_dmz_target_ip": "malformed request"}

class DMZListTargetIP(Resource):
    """
    DMZ list target IP address from dns lookup
    """
    def get(self):
        result_obj = g_ipfw_intf.list_ip_from_tbl("dmzallowlist")
        return {'list_dmz_allow_target_ip': result_obj}
        
api.add_resource(MainPage, '/')
# Inernal network connected device block control
api.add_resource(ListBlockSrcIP, '/list_block_src_ip')
api.add_resource(AddBlockSrcIP, '/add_block_src_ip')
api.add_resource(DelBlockSrcIP, '/del_block_src_ip')
api.add_resource(AddBlockSrcMAC, '/add_block_src_mac')
api.add_resource(DelBlockSrcMAC, '/del_block_src_mac')
# Block target IP for access controlling
api.add_resource(ListBlockTargetIP, '/list_block_target_ip')
api.add_resource(AddBlockTargetIP, '/add_block_target_ip')
api.add_resource(DelBlockTargetIP, '/del_block_target_ip')
# Automatic update the forwarding target IP to bypass firewall
api.add_resource(AddFwdTargetIp, '/add_fwd_target_ip')
api.add_resource(DelFwdTargetIp, '/del_fwd_target_ip')
api.add_resource(ClrFwdTargetIp, '/clr_fwd_target_ip')
# Lockdown internal network device access
api.add_resource(ListLockDownIP, '/list_lockdown_dev_ip')
api.add_resource(AddLockDownIP, '/add_lockdown_dev_ip')
api.add_resource(DelLockDownIP, '/del_lockdown_dev_ip')
# DMZ Access Controlling
api.add_resource(DMZAllowTargetIP, '/add_dmz_target_ip')
api.add_resource(DMZBlockTargetIP, '/del_dmz_target_ip')
api.add_resource(DMZListTargetIP, '/list_dmz_target_ip')
# Strict Access Mode for configured host
#  strict follow DNS lookup result to open target connectivity
#  try dnscrypt_proxy for this case
#
#  ipfw strict_host table skipto subipfw
#   subipfw from host ip to host_tgt_ip_tbl skipto nat    
#  
#  linux dmz fwd host to 192.168.10.84:53 to dnscript_proxy
# Add internal network connected client under strict access control
class AddStrictMonClient(Resource):
    """
    DMZ/Main Router strict access control mode Add device
    """
    def get(self):
        return {'usage': "POST to Add host to strict_hosts_list table"}
    def post(self):
        """
        Post Add new device to strict_hosts_list
        """
        strict_mon_ip_addr = parser.parse_args()['ip_addr']
        if strict_mon_ip_addr:
            return g_ipfw_intf.add_ip_to_skipto_tbl(strict_mon_ip_addr, "strict_hosts_list")
        else:
            return {"add_strict_mon_host": "malformed request"}

class DelStrictMonClient(Resource):
    """
    DMZ/Main Router strict access control mode Del device
    """
    def get(self):
        return {'usage': "POST to Del host to strict_hosts_list table"}
    def post(self):
        """
        Post Add new device to strict_hosts_list
        """
        strict_mon_ip_addr = parser.parse_args()['ip_addr']
        if strict_mon_ip_addr:
            return g_ipfw_intf.del_ip_from_skipto_tbl(strict_mon_ip_addr, "strict_hosts_list")
        else:
            return {"add_strict_mon_host": "malformed request"}

class ListStrictMonClient(Resource):
    """
    DMZ/Main Router strict access control mode list device
    """
    def get(self):
        return g_ipfw_intf.list_ip_from_skipto_tbl("strict_hosts_list")

api.add_resource(AddStrictMonClient, '/add_strict_mon_host')
api.add_resource(DelStrictMonClient, '/del_strict_mon_host')
api.add_resource(ListStrictMonClient, '/list_strict_mon_host')

class AddTargetForMonClient(Resource):
    """
    DMZ/Main Router add access target ip for strict mon host
    """
    def get(self):
        return {"usage": "POST to Add target IP address for mon host"}
    def post(self):
        """
        POST Add target IP to mon host access table
        """
        strict_mon_ip_addr = parser.parse_args()["mon_addr"]
        target_ip_addr = parser.parse_args()['ip_addr']
        if strict_mon_ip_addr and target_ip_addr:
            print("add target ", strict_mon_ip_addr, " target_ip ", target_ip_addr)
            idx = strict_mon_ip_addr.rsplit('.')[3]
            tbl_name = "t{num}".format(num=idx.zfill(3))
            return g_ipfw_intf.add_ip_to_tbl(target_ip_addr, tbl_name)
        else:
            return {"add_target_for_strict_host": "malformed request"}

class DelTargetForMonClient(Resource):
    """
    DMZ/Main Router del access target ip from strict mon host
    """
    def get(self):
        return {"usage": "POST to Del target IP address from mon host"}
    def post(self):
        """
        POST Del target IP from mon host access table
        """
        strict_mon_ip_addr = parser.parse_args()["mon_addr"]
        target_ip_addr = parser.parse_args()["ip_addr"]
        if strict_mon_ip_addr and target_ip_addr:
            idx = strict_mon_ip_addr.rsplit('.')[3]
            tbl_name = "t{num}".format(num=idx.zfill(3))
            return g_ipfw_intf.del_ip_from_tbl(target_ip_addr, tbl_name)
        else:
            return {"del_target_for_strict_host": "malformed request"}

class ListTargetForMonClient(Resource):
    """
    DMZ/Main Router list access target ip from strict mon host
    """
    def get(self):
        mon_addr = parser.parse_args()["mon_addr"]
        if mon_addr:
            idx = mon_addr.rsplit('.')[3]
            tbl_name = "t{num}".format(num=idx.zfill(3))
            return g_ipfw_intf.list_ip_from_tbl(tbl_name)
        else:
            return {"list_target_for_strict_host": "malformed request"}

class CleanTargetForMonClient(Resource):
    """
    DMZ/Main Router clean all target IP from strict mon host table
    """
    def get(self):
        return {"usage": "POST to clean all from mon host table"}
    def post(self):
        """
        POST Clean all IP from mon target table
        """
        mon_addr = parser.parse_args()["mon_addr"]
        if mon_addr:
            idx = mon_addr.rsplit('.')[3]
            tbl_name = "t{num}".format(num=idx.zfill(3))
            return g_ipfw_intf.flush_tbl(tbl_name)
        else:
            return {"clean_taget_for_strict_host": "malformed request"}


# Add allowed target IP for strict controlled client within internal network
api.add_resource(AddTargetForMonClient, '/add_target_for_strict_host')
api.add_resource(DelTargetForMonClient, '/del_target_for_strict_host')
api.add_resource(ListTargetForMonClient, '/list_target_for_strict_host') 
api.add_resource(CleanTargetForMonClient, '/clean_target_for_strict_host')

if __name__ == '__main__':
    app.run(ssl_context='adhoc', host="192.168.10.1", port=6466)
