#!/bin/bash
lm=../loadmodule.sh 
for host in 192.168.0.13 192.168.0.10 #192.168.0.10 
do
cd netfilter
$lm $host ip_tables.o
ssh root@$host iptables -F \; iptables -t mangle -F \; rmmod ipt_BOUNCE \; rmmod ipt_REJECT.o
$lm $host ipt_BOUNCE.o
$lm $host ipt_REJECT.o
done
