#!/usr/bin/perl -w


#my $GCC="gcc33";
my $GCC="gcc32";
my $MKDEP="/local/ashieh/linux-trickles-uml-merge.host/scripts/mkdep.bin";

my @mkdepargs = @ARGV;
my @gccargs = map {
	my $a = $_;
	my @result;
	if($a eq "--" || $a =~ /\.h$/) {
		@result = ();
	} else {
		@result = ($a);
	}
	@result;
} @mkdepargs;

if(1) {
	open(GCC, "-|", $GCC, "-M", @gccargs);
	while(<GCC>) {
		print $_;
	}
}
open(MKDEP, "-|", $MKDEP, @mkdepargs);


while(<MKDEP>) {
	print $_;
}

