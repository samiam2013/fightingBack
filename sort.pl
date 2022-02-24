#!/usr/bin/perl

use strict;
use warnings;
use diagnostics;

use Getopt::Long;
use Data::Dumper;
use List::MoreUtils; # cpan install List::MoreUtils
use URI::Query; # cpan install URI::Query

my $verbose;
GetOptions("verbose"  => \$verbose);

# expecting to find this file in the same directory
my $file_path = './http_exploit_requests.log';
open my $requests_fh, $file_path or die "Could not open $file_path: $!";

my @requests = [];
while (my $line = <$requests_fh>) {
    if ($line =~ /GET\s([^\s]+)/) {
        my $request = $1; # first matching group from latest regex compare
        #print STDOUT "request: $request\n" if $verbose;
        push @requests, $request;
    }
}

@requests = sort @requests;
@requests = List::MoreUtils::uniq @requests;
print STDOUT Data::Dumper::Dumper \@requests if $verbose;

# create a new request_paths array without the query string (everything after ? in urls)
my @request_paths = [];
for my $request (@requests){
    if ($request =~ /^(.*)\?([^\s]+)$/){
        push @request_paths, lc $1; # case insensitivity in nginx with `locatoin ~* ^<pattern>`
        my $query_hashref = URI::Query->new($2);
        my %hash = $query_hashref->hash;
        #print STDOUT Data::Dumper::Dumper \%hash if $verbose;
        my $hash_length = scalar keys %hash;
        #print STDOUT Data::Dumper::Dumper $hash_length if $verbose;
        if (($hash_length != 1 or not defined $hash{'lang'}) and $verbose) {
            print STDOUT "scalar non lang=en query string:\n";
            print STDOUT Data::Dumper::Dumper \%hash;
        }
    }
}

@request_paths = List::MoreUtils::uniq @request_paths;
print STDOUT Data::Dumper::Dumper \@request_paths if $verbose;

my @patterns = (
    '(my)?admin(\/(db|index|pma|phpmyadimin|sqladmin|web)|istrator\/(pma|admin|php))?',
    '(pma|(_|[\d])?php|database|(shop)?db|(my)?sql|xmlrpc)',
);

for my $path (@request_paths) {
    my $matched = 0;
    for my $pattern (@patterns) {
        if (lc $path =~ /^\/$pattern.*/ ) {
            $matched = 1;
            # this line needs to be kept in lockstep with the above regex
            print STDOUT "path $path  matched pattern /^\\/$pattern.*/ matched\n" if $verbose;
        }
    }
    unless ($matched) {
        print STDOUT "path '$path' not matched by any pattern\n"; #if $verbose;
    }
} 

# null in ascii 78, 86, 76, 76
my $HONEY_PORT = 7886;
my $HONEY_HOST = 'http://127.0.0.1';

my $nginx_config = '';
for my $pattern (@patterns){
    $nginx_config .= "location ~* ^/$pattern/ {\n";
    $nginx_config .= "\t# auto generated proxy to honeypot\n";
    $nginx_config .= "\tproxy_pass $HONEY_HOST:$HONEY_PORT\$request_uri;\n";
    $nginx_config .= "}\n\n";
}

print STDOUT "\n$nginx_config";

exit;