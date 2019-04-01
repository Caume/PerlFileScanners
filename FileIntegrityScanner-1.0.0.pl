#!/usr/bin/perl
# FileIntegrityScanner v.1.0.0
# (c)2018-2019 by Omar A. Herrera Reyna. This program is licensed under GPLv3.
#  
use strict;
use Crypt::Digest::SHA1 qw( sha1_file_hex );
use Text::CSV;
use Getopt::Std;
use File::Find;
use File::Spec;
#use open "IN" => ":bytes", "OUT" => ":utf8";

our($opt_p, $opt_t);
my $scanDelay = 30;
my $key;
my $inputFile;
my %scanPatternSHA1_HEX;
my %scanPatternCmdIfOK;
my %scanPatternCmdIfBAD;
my @output;
my $FileHashHEX;

print ("FileIntegrityScanner (c) 2018-2019 v.1.0.0 by Omar A. Herrera Reyna. Licensed under GPLv3.\n");
getopts("t:p:");
if (!@ARGV || !$opt_p) {
	print ("Error, incorrect syntax.\nUsage: $0 [ -t scan_delay ] < -p signature_file_path > <directory_path1> [directory_path2] [directory_path3] ...\n");
	exit(1);
}
if ($opt_t){
    $scanDelay = $opt_t;
    }
    
print ("-- Using pattern file: $opt_p\n");
print ("-- Using scan delay (sec): $scanDelay\n");

sub fileScan {
    $inputFile=File::Spec->rel2abs($_);#Convert file path to an absolute path.
    if (-d) { #Process only regular files of specific type.
	} elsif ( exists ($scanPatternSHA1_HEX{$inputFile}) ) { 
	      $FileHashHEX= sha1_file_hex ($inputFile);
	      print( "FILE: " . $FileHashHEX . " - " . $inputFile . "\n");
	      print( "HASH: " . $scanPatternSHA1_HEX{$inputFile} . " - " . $inputFile . "\n");
	      if ($scanPatternSHA1_HEX{$inputFile} eq $FileHashHEX){
		@output = `$scanPatternCmdIfOK{$inputFile}`;
	      } else {
		@output = `$scanPatternCmdIfBAD{$inputFile}`;		  
	      }
		print(@output);
	} 
}

my $csv = Text::CSV->new( { binary => 1, eol => $/, allow_whitespace => 1 } ); # Double doublequotes to escape them
open (CSV, "<", $opt_p) || die ("* ERROR $! : can't open file with patterns: $opt_p \n");
while (<CSV>) { # Get signatures from signature CSV file.
	next if ($. == 1);  #Skip first line (headers).
	if ($csv->parse($_)) {
		my @columns = $csv->fields();
	        $key = $columns[0]; # Filename with absolute path (KEY)
		$scanPatternSHA1_HEX{$key}=$columns[1]; # SHA1 Hexadecimal HASH
		$scanPatternCmdIfOK{$key}=$columns[2]; # System Command to execute if file hash matches SHA1 HASH
		$scanPatternCmdIfBAD{$key}=$columns[3]; # System Command to execute if file hash does not match SHA1 HASH
	} else {
		my $err = $csv->error_input;
		print "Failed to parse signature file, line: $err";
	}
}
close (CSV);

while (1){
    find(\&fileScan, @ARGV);
    sleep $scanDelay;
}
