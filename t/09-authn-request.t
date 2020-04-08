use Test::More;
use strict;
use warnings;
use Net::SAML2;

my $ar = Net::SAML2::Protocol::AuthnRequest->new(
        issuer => 'http://some/sp',
        destination => 'http://some/idp',
        nameid_format => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
);
ok($ar);
my $xml = $ar->as_xml;
ok($xml);
#diag($xml);

like($xml, qr/ID=".+"/);
like($xml, qr/IssueInstant=".+"/);

done_testing;
