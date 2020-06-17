# -*- perl -*-
BEGIN {
  unless ($ENV{AUTHOR_TESTING}) {
    print qq{1..0 # SKIP these tests are for testing by the author\n};
    exit
  }
}


use strict;
use warnings;

use Test::More qw/ no_plan /;
use File::Which;


BEGIN {
    use_ok( 'XML::Sig' );
}

SKIP: {
    skip "xmlsec1 not installed", 4 unless which('xmlsec1');

    # Try whether xmlsec is correctly installed which 
    # doesn't seem to be the case on every cpan testing machine

    my $output = `xmlsec1 --version`;
    skip "xmlsec1 not correctly installed", 6 if $?;

    my $xml = '<?xml version="1.0"?>'."\n".'<foo ID="NETSAML_1">'."\n".'<bar>123</bar>'."\n".'</foo>';
    my $sig = XML::Sig->new( { key => 't/rsa.private.key', cert => 't/rsa.cert.pem' } );
    # xml-sig.key.pem,xml-sig.cert.pem,intermediate.pem,ca-chain.cert.pem
    ok( open PXML, '>', 'plain.xml' );
    print PXML $xml;
    close PXML;
    my $signed = $sig->sign($xml);
    ok( $signed, "Got XML for the response" );
    ok( open XML, '>', 'tmp.xml' );
    print XML $signed;
    close XML;
    my $verify_response = `xmlsec1 --verify --insecure --id-attr:ID foo tmp.xml 2>&1`;
    ok( $verify_response =~ m/^OK/, "Response is OK for xmlsec1" )
        or warn "calling xmlsec1 failed: '$verify_response'\n";

    #unlink 'tmp.xml';

    my $sig2 = XML::Sig->new( { key => 't/dsa.private.key' } );
    my $result = $sig2->verify($signed);
    ok( $result, "XML Signed Properly" );
}
