#!/usr/bin/perl -w

use strict;
my $LINE = 0;

die unless @ARGV == 2;
my ($ifname, $ofname) = @ARGV;

open(INPUT,"<$ifname") or die "could not open $ifname";
open(OUTPUT,">$ofname") or die "could not open $ofname";

my $prev_line = "";
my $outputLineNum = 1;

sub printMutlilineString($) {
  my $string = shift;
  my @strings = split("\n", $string);
  my $num_newlines = @strings;
  print OUTPUT join("", (map { "$_\n" } @strings));
  return $num_newlines;
}

while(my $line = <INPUT>) {
  if($line =~ /_deleteCell/) {
    if($prev_line =~ /^#/) {
      if($LINE) {
	$prev_line = "# " . ($outputLineNum + 1) . " \"$ofname\"\n";
      } else {
	$prev_line = "";
      }
    }
    $line =~ s/([{};])/$1\n/g;
  }
  if(!$LINE && ($line =~ /^#/)) {
    $line = "";
  }
  $outputLineNum += printMutlilineString($prev_line);
  $prev_line = $line;
}

print OUTPUT $prev_line;
