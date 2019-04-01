#!/usr/bin/perl
# LogScanner v.1.0.0
# (c)2019 by Omar A. Herrera Reyna. This program is licensed unde GPLv3.
#  
use Text::CSV;
use Getopt::Std;
use File::Find;
use File::Spec;
use open "IN" => ":bytes", "OUT" => ":utf8";

print "# LogScanner (c) 2019 by Omar A. Herrera Reyna. This program is licensed unde GPLv3.\n";
getopts("c:p:");
if (!@ARGV || !$opt_p) {
	print "Error, incorrect syntax.\nUsage: $0 -p <signature_file_path> <directory_path1> [directory_path2] [directory_path3] ...\n";
	exit(1);
}
print "# Using pattern file: $opt_p\n";
my $mMinC = 0; #Minimum context chars before/after match ($1) to save.
my $mMaxC = 0; #Maximum context chars before/after match ($1) to save.
my $pStart = "(.{$mMinC,$mMaxC}";
my $pEnd =".{$mMinC,$mMaxC})";
sub fileScan {
	if (-d) { #Process only regular files of specific type.
	} 
	elsif(m/(^.*\.(log|syslog|evtx?).*$)/i){ #Check allowed file extensions (add your own if necessary)
		$inputFile=File::Spec->rel2abs($_);#Convert file path to an absolute path.
		open (INPUT, "<",$inputFile) || die ("* ERROR $! : can't open file: $inputFile\n");
		binmode (INPUT); #Open file in binary mode.
		undef $/; #Clear input record separator to read the whole file as a single string.		
		while (<INPUT>){ #Scan file for pattern.
			while(($key,$scanPattern) = each (%scanPatterns)){ 
				while (m/$pStart$scanPattern$pEnd/gims){
					eval $scanPatternPrintStr{$key}; #Execute print instructions from pattern file
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
		$scanPatternName{$key}=$columns[1]; #Add pattern name to corresponding hash.
		$scanPatternDescription{$key}=$columns[2]; #Add pattern description to corresponding hash.
		$scanPatternAuthor{$key}=$columns[3]; #Add pattern author to corresponding hash.
		$scanPatternPrintStr{$key}=$columns[4]; #Add pattern print instructions (Perl code) to corresponding hash.
		$scanPatterns{$key}=$columns[5]; #Add pattern regex to corresponding hash.
	} else {
		my $err = $csv->error_input;
		print "Failed to parse signature file, line: $err";
	}
}
close (CSV);
find(\&fileScan, @ARGV);