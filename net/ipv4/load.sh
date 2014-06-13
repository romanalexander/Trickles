dest=192.168.0.10

ssh root@$dest killall server-skip client7
./loadmodule.sh $dest trickles-mod.o

