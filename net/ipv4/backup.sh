dest=$1

if [[ -z "$dest" ]] ; then
	echo "Dest not specified"
	exit
fi

echo cp smallMakefile Makefile *.c *.h *.pl $dest

