#!/usr/bin/perl -w

my $count = 0;
print "define fields\n";
while(<>) {
  chomp;
  my $foo = $_;
  $foo =~ s/^\s+//;
  $foo =~ s/\s+$//;
  my $tmp = "&((struct cminisock*)0)->$foo";
#print $tmp
  print "set \$a=(int) $tmp
printf \"%d:\\t $foo\\n\", \$a
";
  $count++;
}

print "end\nfields\n"
