use Test::More;
use Net::SAML2;
use File::Slurp qw(read_file);

$cert = 't/sign-nopw-cert.pem';
$key  = 't/sign-nopw-cert.pem';
$cacert = 't/cacert.pem';

my $sp = Net::SAML2::SP->new(
        id               => 'http://localhost:3000',
        url              => 'http://localhost:3000',
        cert             => $cert,
        key              => $key,
        cacert           => $cacert,
        org_name         => 'Test',
        org_display_name => 'Test',
        org_contact      => 'test@example.com',
);
ok($sp);
ok($sp->metadata);

my $xml = $sp->metadata;
my $xpath = XML::XPath->new( xml => $xml );
$xpath->set_namespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

my @ssos = $xpath->findnodes('//md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService');
ok($ssos[0]->getAttribute('Binding') eq 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');

# repeat tests for text cert files
$cert_text = read_file($cert);
$key_text = read_file($key);
$cacert_text = read_file($cacert);

my $sp_text = Net::SAML2::SP->new(
        id               => 'http://localhost:3000',
        url              => 'http://localhost:3000',
        cert             => $cert_text,
        key              => $key_text,
        cacert           => $cacert_text,
        org_name         => 'Test',
        org_display_name => 'Test',
        org_contact      => 'test@example.com',
        certs_as_string  => 1,
);
ok($sp_text);
ok($sp_text->metadata);

my $xml = $sp_text->metadata;
my $xpath = XML::XPath->new( xml => $xml );
$xpath->set_namespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

my @ssos = $xpath->findnodes('//md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService');
ok($ssos[0]->getAttribute('Binding') eq 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');


done_testing;
