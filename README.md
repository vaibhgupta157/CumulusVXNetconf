# CumulusVXNetconf
Cumulus Linux is an open network operating system. Network Command Line Utility(NCLU) is command interface for inspection and modification of configuration data in Cumulus Linux environment. CumulusVXNetconf is an attempt to build netconf capability in Cumulus Linux. It does not use any yang model and payload for netconf rpc messages are net commands. 

# Installation
Run the script:
```
../CumulusVXNetconf$./setup.sh
```
This script requires sudo password and will ask for restart :
```
do you want to restart your computer to apply changes in /etc/environment file? yes(y)no(n)
```
Note: Do not run sudo ./setup.sh
Successful installation can be tested by checking value of env variable NETCONF_DIR which is path of CumulusVXNetconf directory
```
../CumulusVXNetconf$echo $NETCONF_DIR
```
 
# Run Netconf Server 
Run netconf_server_candidate.py using following:
```
../CumulusVXNetconf$python netconf_server_candidate.py --port <port> --username <user> --password <pass>
```
By default, port is 8300, username is "admin" and password is "admin"
 
# RPC Examples
Once server is successfully started, then a netconf client can connect to the port specified. CumulusVXNetconf has candidate capability and can modify configuration in candidate datastore only.

Some examples of get, get-config, edit-config:\
get:\
In get rpc can be sent with or without filter. Filter is simply a "net show" command.
```
<get>
<filter>net show interface swp1</filter>
</get>
```

get-config:
```
<get-config>
<source><running/></source>
</get-config>
```
Source can be candidate as well

edit-config:\
edit-config can only be performed on candidate datastore. Any configuration change pushed to candidate store has to be committed to running to make configuration active.
```
<edit-config>
<target><candidate/></target>
<config>
<cmd>net add ospf</cmd>
<cmd>net add interface swp1 bridge access vlan 100</cmd>
...
</config>
</edit-config>
```

validate:\
Configuration pushed in candidate datastore can be validated before committing.
```
<validate>
<source><candidate/></source>
</validate>
```

commit:\
Configuration pushed in candidate datastore can be committed to running:
```
<commit/>
```

copy-config:\
This RPC is used for copying running datastore configuration to candidate datastore.
```
<copy-config>
<source><running/></source>
<target><candidate/></target>
</copy-config>
```
