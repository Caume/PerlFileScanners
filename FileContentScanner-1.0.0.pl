#!/usr/bin/perl
# FileContentScanner v.1.0.0
# (c)2019 by Omar A. Herrera Reyna. This program is licensed unde GPLv3.
#  
use Text::CSV;
use Getopt::Std;
use File::Find;
use File::Spec;
use open "IN" => ":bytes", "OUT" => ":utf8";

print "# FileContentScanner (c) 2019 v.1.0 by Omar A. Herrera Reyna. Licensed under GPLv3.\n";
#my $signatureFP = shift (@ARGV);
getopts("c:p:");
if (!@ARGV || !$opt_p) {
  print "Error, incorrect syntax.\nUsage: $0 -p <signature_file_path> -c [max_context_characters default=20]  <directory_path1> [directory_path2] [directory_path3] ...\n";
  exit(1);
}
print "# Using pattern file: $opt_p\n";
my $mMinC = 0; #Minimum context chars before/after match to save.
my $mMaxC = $opt_c || 20; #Maximum context chars before/after match to save.
my $pStart = "(.{$mMinC,$mMaxC}";
my $pEnd =".{$mMinC,$mMaxC})";

sub fileScan {
	if (-d) { #Process only regular files of specific type.
	} elsif(/^([^\.]+$)|(^.*\.(s?html?|aspx?|php|txt|js|jsp|pl|cgi).*$)/i){
		$inputFile=File::Spec->rel2abs($_);#Convert file path to an absolute path.
		open (INPUT, "<",$inputFile) || die ("* ERROR $! : can't open file: $inputFile\n");
		binmode (INPUT); #Open file in binary mode.
		undef $/; #Clear input record separator to read the whole file as a single string.		
		while (<INPUT>){ #Scan file for pattern.
			while(($key,$scanPattern) = each (%scanPatterns)){ 
				while (m/$pStart$scanPattern$pEnd/gims){
					$token=$2;
					$offset=$-[2];
					($processedContext=$1)=~ s/\R//g;
					$processedContext =~ s|"|""|g;
					print "\"$inputFile\",\"$key\",\"$token\",\"$offset\",\"$scanPatternRegulation{$key}\",\"$scanPatternDescription{$key}\",\"$processedContext\"\n"; #print result CSV headers
				}
			}
		}
		close (INPUT);     
	} 
}
my $csv = Text::CSV->new( { binary => 1, eol => $/, allow_whitespace => 1 } );
open (CSV, "<", $opt_p) || die ("* ERROR $! : can't open file with patterns: $opt_p \n");
while (<CSV>) { #Get signatures from signature CSV file.
	next if ($. == 1);  #Skip first line (headers).
	if ($csv->parse($_)) {
		my @columns = $csv->fields();
		$key = $columns[0]; #Get key for the hash value.
		$scanPatternRegulation{$key}=$columns[1]; #Add regulation name to corresponding hash.
		$scanPatternLanguage{$key}=$columns[2]; #Add regulation language to corresponding hash.
		$scanPatternDescription{$key}=$columns[3]; #Add description to corresponding hash.
		$scanPatternTypes{$key}=$columns[4]; #Add type to corresponding hash.
		$scanPatterns{$key}=$columns[5]; #Add pattern to corresponding hash.
	} else {
		my $err = $csv->error_input;
		print "Failed to parse signature file, line: $err";
	}
}
close (CSV);
print "\"file\",\"key\",\"token\",\"offset\",\"regulation\",\"description\",\"context\"\n"; #Print result CSV headers.
find(\&fileScan, @ARGV);