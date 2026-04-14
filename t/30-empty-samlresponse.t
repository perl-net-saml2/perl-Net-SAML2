use strict;
use warnings;
use Test::Lib;
use Test::Net::SAML2;

use Net::SAML2::Protocol::Assertion;
use MIME::Base64;

my $xml = '';

my $response = encode_base64($xml);

my $sp = net_saml2_sp();

my $post = $sp->post_binding;

my $response_xml;

throws_ok(
    sub {
        $response_xml = $post->handle_response($response);
    },
    qr/Net::SAML2::Binding::POST::handle_response\(\) verify_xml failed/,
    '$sp->handle_response throws exception for empty xml'
);

throws_ok(
    sub {
        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(xml => $xml);
    },
    qr/Net::SAML2::XML::Util::no_comments/,
    'Net::SAML2::Protocol::Assertion->new_from_xml throws exception for empty XML'
);

done_testing;
