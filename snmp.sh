sudo yum -y install net-snmp net-snmp-utils
systemctl start snmpd
echo "rocommunity public 0.0.0.0/0" > /etc/snmp/snmpd.conf
systemctl restart  snmpd
systemctl enable snmpd
