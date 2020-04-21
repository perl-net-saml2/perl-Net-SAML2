use Test::More;
use strict;
use warnings;
use Net::SAML2;
use Net::SAML2::XML::Sig;
use File::Slurp qw(read_file);

use Crypt::OpenSSL::Random;

my $request_id = 'NETSAML2_' . unpack 'H*', Crypt::OpenSSL::Random::random_pseudo_bytes(16);

my $ar = Net::SAML2::Protocol::AuthnRequest->new(
        id => $request_id,
        issuer => 'http://some/sp',
        destination => 'http://some/idp',
        nameid_format => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
);
ok($ar);
my $xml = $ar->as_xml;
ok($xml);
like($xml, qr/ID="$request_id"/);
like($xml, qr/IssueInstant=".+"/);

my $signer = Net::SAML2::XML::Sig->new({
    canonicalizer => 'XML::CanonicalizeXML',
    key => 't/sign-nopw-cert.pem',
    cert => 't/sign-nopw-cert.pem',
});
ok($signer);

# create a signature
my $signed = $signer->sign($xml);
ok($signed);

my $verify = $signer->verify($signed);
ok($verify);

my $cert = read_file('t/sign-nopw-cert.pem');
ok($cert);
my $key = read_file('t/sign-nopw-cert.pem');
ok($key);
my $signer_text = Net::SAML2::XML::Sig->new({
    canonicalizer => 'XML::CanonicalizeXML',
    key => $key,
    cert => $cert,
    certs_as_string => 1,
});

ok($signer_text);

# create a signature
my $signed_text = $signer_text->sign($xml);
ok($signed_text);

my $verify_text = $signer_text->verify($signed);
ok($verify_text);
done_testing;
