use strict;
use warnings;
use Test::Lib;
use Test::Net::SAML2;

my $sp = net_saml2_sp();

my $xpath = get_xpath(
    $sp->metadata,
    md => 'urn:oasis:names:tc:SAML:2.0:metadata',
    ds => 'http://www.w3.org/2000/09/xmldsig#'
);

my $nodes = $xpath->findnodes('//md:EntityDescriptor/md:SPSSODescriptor');
is($nodes->size, 1, "We have one PSSODescriptor");
my $node = $nodes->get_node(1);
ok(!$node->getAttribute('WantAssertionsSigned'),
    'Wants assertions to be signed');
ok(
    !$node->getAttribute('AuthnRequestsSigned'),
    '.. and also authn requests to be signed'
);

my @ssos = $xpath->findnodes(
    '//md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService');

if (is(@ssos, 2, "Got two assertionConsumerService(s)")) {
    is(
        $ssos[0]->getAttribute('Binding'),
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        "Returns the correct binding: HTTP-POST"
    );
    is(
        $ssos[1]->getAttribute('Binding'),
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
        "Returns the correct binding: HTTP-Artifact"
    );
}

{
    my $sp = Net::SAML2::SP->new(
        id               => 'http://localhost:3000',
        url              => 'http://localhost:3000',
        cert             => 't/sign-nopw-cert.pem',
        key              => 't/sign-nopw-cert.pem',
        cacert           => 't/cacert.pem',
        org_name         => 'Test',
        org_display_name => 'Test',
        org_contact      => 'test@example.com',
        org_url          => 'http://www.example.com',
        slo_url_soap     => '/slo-soap',
        slo_url_redirect => '/sls-redirect-response',
        slo_url_post     => '/sls-post-response',
        acs_url_post     => '/consumer-post',
        acs_url_artifact => '/consumer-artifact',
        org_name         => 'Net::SAML2 Saml2Test',
        org_display_name => 'Saml2Test app for Net::SAML2',
        org_contact      => 'saml2test@example.com',
        error_url        => '/error',
    );

    my $xpath = get_xpath($sp->metadata,
        md => 'urn:oasis:names:tc:SAML:2.0:metadata');
    my $nodes = $xpath->findnodes('//md:EntityDescriptor/md:SPSSODescriptor');
    is($nodes->size, 1, "We have one PSSODescriptor");
    my $node = $nodes->get_node(1);
    ok($node->getAttribute('WantAssertionsSigned'),
        'Wants assertions to be signed');
    ok(
        $node->getAttribute('AuthnRequestsSigned'),
        '.. and also authn requests to be signed'
    );
}

$nodes = $xpath->findnodes('//ds:Signature');
is($nodes->size(), 1, "We have a signed metadata document ds:Signature present");

{
    my $sp = net_saml2_sp(sign_metadata => 0);
    my $xpath = get_xpath(
        $sp->metadata,
        md => 'urn:oasis:names:tc:SAML:2.0:metadata',
        ds => 'http://www.w3.org/2000/09/xmldsig#'
    );

    my $nodes = $xpath->findnodes('//ds:Signature');
    is($nodes->size(), 0, "We don't have any ds:Signature present");

}

done_testing;
