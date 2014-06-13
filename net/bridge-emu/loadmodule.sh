#!/bin/sh
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# Copyright (C) Amit S. Kale, 2002.
#
# This script loads a module on a target machine and generates a gdb script.
# source generated gdb script to load the module file at appropriate addresses
# in gdb.
#
# Usage: 
# Loading the module on target machine and generating gdb script)
#	[foo]$ loadmodule.sh <machine> <modulename>
#
# Loading the module file into gdb
#	(gdb) source <gdbscriptpath>
#
# Modify following variables according to your setup. 
#	GDBSCRIPTS - The directory where a gdb script will be generated
#
# Author: Amit S. Kale (akale@veritas.com).
#
# If you run into problems, please check files pointed to by following
# variables.
#	ERRFILE - /tmp/<machine><modulename>.errs contains stderr output of insmod
#	MAPFILE - /tmp/<machine><modulename>.map contains stdout output of insmod
#	GDBSCRIPT - $GDBSCRIPTS/load<machine><modulename> gdb script.

GDBSCRIPTS=/home/ashieh/gdbscripts

if [ $# -lt 2 ] ; then {
	echo Usage: $0 machine modulefile
	exit
} ; fi

TESTM=$1
MFILE=$2
MFILEBASE=`basename $MFILE`

if [ $MFILE = $MFILEBASE ] ; then {
	MFILE=`pwd`/$MFILE
} fi

ERRFILE=/tmp/$TESTM$MFILEBASE.errs
MAPFILE=/tmp/$TESTM$MFILEBASE.map
GDBSCRIPT=$GDBSCRIPTS/load$TESTM$MFILEBASE

function findaddr() {
	local ADDR=0x$(echo "$SEGMENTS" | \
		grep "$1" | sed 's/^[^ ]*[ ]*[^ ]*[ ]*//' | \
		sed 's/[ ]*[^ ]*$//')
	echo $ADDR
}

function checkerrs() {
	if [ "`cat $ERRFILE`" != "" ] ; then {
		cat $ERRFILE
	} fi
}

#load the module
echo Copying $MFILE to $TESTM
scp $MFILE root@${TESTM}:

echo Loading module $MFILE
ssh -l root $TESTM  /sbin/insmod -f -m ./`basename $MFILE` \
	> $MAPFILE 2> $ERRFILE &
sleep 5
checkerrs

SEGMENTS=`awk "BEGIN {
 seg = 0
}
/^$/ {
 if (seg) {
  seg = 0
 }
}
//{
 if (seg) {
  print
 }
}
/^Sections:/ {
 seg = 1
}" $MAPFILE`
#icc confuses the following pattern
#TEXTADDR=$(findaddr "\\.text")
TEXTADDR=$(findaddr "\\.text[^.]")
#TEXTADDR=$(findaddr "\\.text[^1.]")
LOADSTRING="add-symbol-file $MFILE $TEXTADDR"
SEGADDRS=`echo "$SEGMENTS" | awk '//{
	if ($1 != ".text" && $1 != ".this" &&
	    $1 != ".kstrtab" && $1 != ".kmodtab") {
		print " -s " $1 " 0x" $3 " "
	}
}'`
LOADSTRING="$LOADSTRING $SEGADDRS"
echo Generating script $GDBSCRIPT
echo $LOADSTRING > $GDBSCRIPT
