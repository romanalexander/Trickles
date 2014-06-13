#!/usr/bin/perl -w

while(<>) {
  s{//.+$}{}g;
  s{/\*.+?\*/}{}g;
  s/struct\s+//g;
  s/^\s*\S+\s+//g;
  s/,/\n/g;
  s/^\s+//g; s/\s+$//g;
  s/[;*]//g;
  if($_ ne "") {
    print "$_\n";;
  }
}
