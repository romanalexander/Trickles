#!/bin/sh

dests="192.168.0.10 192.168.0.13 192.168.0.11"
files="trickles-mod.o"

cp $files /home/ashieh/trickles/multi/local/testpkg

for dest in $dests ; do
	scp $files root@$dest:~/
	echo $dest
	ssh root@$dest killall server-skip client7
	ssh root@$dest rmmod.old trickles-mod \; insmod.old -f trickles-mod.o
done


( cd /home/ashieh/trickles/multi/local ; ./local-install.sh )

