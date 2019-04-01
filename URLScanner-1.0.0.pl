#!/usr/bin/perl
# URLScanner-1.0.0
# (c) 2019 by Omar A. Herrera Reyna. This program is licensed unde GPLv3.
# 
# Check URL parameter file:
my $urlListFile=$ARGV[0];

if (!$urlListFile)
{
  print "Error, incorrect syntax.\nUsage: $0 <file with url list to scan>\n";
  exit(1);
}
if (!(-s $urlListFile))
{
  print "Error, file with URL does not exist or is empty: $URLlist\n";
  exit(2);
}
# Open URL parameter file and process each line:
open (FH, "<", $urlListFile) || die "Cannot open file: $urlListFile !\n";
while (<FH>)
{
  chomp;
  /^https?:\/\/([^\/]+).*/i;
  print "domain for $_ is $1 \n";
} 