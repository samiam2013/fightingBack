#!/usr/bin/perl

use strict;
use warnings;
use diagnostics;

use Getopt::Long;
use Data::Dumper;
use List::MoreUtils; # cpan install List::MoreUtils
use URI::Query; # cpan install URI::Query

my ($verbose, $input_path, $output_path, $proxy_host, $proxy_port) = (
    0,
    './http_exploit_requests.log',
    './honeypost_nginx.conf',
    '127.0.0.1', 
    7886 );
GetOptions("verbose"  => \$verbose, 
            "input|i=s" => \$input_path,
            "output|o=s" => \$output_path,
            "host=s" => \$proxy_host,
            "port=s" => \$proxy_port);

open my $requests_fh, $input_path or die "Could not open $input_path: $!";

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


my $nginx_config = '';
for my $pattern (@patterns){
    $nginx_config .= "location ~* ^/$pattern/ {\n";
    $nginx_config .= "\t# auto generated proxy to honeypot\n";
    $nginx_config .= "\tproxy_pass http://$proxy_host:$proxy_port\$request_uri;\n";
    $nginx_config .= "}\n\n";
}

print STDOUT "attempting to print config to $output_path\n$nginx_config" if $verbose;
open NGINX_CONF, '>', $output_path or die $!;
print NGINX_CONF $nginx_config;
close NGINX_CONF;

exit;