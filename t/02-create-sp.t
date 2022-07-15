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

my $node
    = get_single_node_ok($xpath, '//md:EntityDescriptor/md:SPSSODescriptor');
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

get_single_node_ok($xpath, '//ds:Signature');

{
    my $sp    = net_saml2_sp(sign_metadata => 0);
    my $xpath = get_xpath(
        $sp->metadata,
        md => 'urn:oasis:names:tc:SAML:2.0:metadata',
        ds => 'http://www.w3.org/2000/09/xmldsig#'
    );

    my $nodes = $xpath->findnodes('//ds:Signature');
    is($nodes->size(), 0, "We don't have any ds:Signature present");

}

{
    my $sp = Net::SAML2::SP->new(
        id     => 'Some entity ID',
        url    => 'http://localhost:3000',
        cert   => 't/sign-nopw-cert.pem',
        key    => 't/sign-nopw-cert.pem',
        cacert => 't/cacert.pem',

        org_name         => 'Net::SAML2::SP',
        org_display_name => 'Net::SAML2::SP testsuite',
        org_contact      => 'test@example.com',

        org_url          => 'http://www.example.com',
        slo_url_soap     => '/slo-soap',
        slo_url_redirect => '/sls-redirect-response',
        slo_url_post     => '/sls-post-response',
        acs_url_post     => '/consumer-post',
        acs_url_artifact => '/consumer-artifact',
        error_url        => '/error',
    );

    my $xpath = get_xpath(
        $sp->metadata,
        md => 'urn:oasis:names:tc:SAML:2.0:metadata',
        ds => 'http://www.w3.org/2000/09/xmldsig#'
    );

    my $node = get_single_node_ok($xpath, '/md:EntityDescriptor');
    is(
        $node->getAttribute('entityID'),
        'Some entity ID',
        '.. has the correct entity ID'
    );

    ok($node->getAttribute('ID'), '.. has an ID');

    {
        # Test ContactPerson
        my $node = get_single_node_ok($xpath, '/node()/md:ContactPerson');
        my $p    = $node->nodePath();

        my $company = get_single_node_ok($xpath, "$p/md:Company");
        is(
            $company->textContent,
            'Net::SAML2::SP testsuite',
            "Got the correct company name for the contact person"
        );

        my $email = get_single_node_ok($xpath, "$p/md:EmailAddress");
        is($email->textContent, 'test@example.com',
            ".. and the correct email");
    }

    {
        # Test Organisation
        my $node = get_single_node_ok($xpath, '/node()/md:Organization');
        my $p    = $node->nodePath();

        my $name = get_single_node_ok($xpath, "$p/md:OrganizationName");
        is($name->textContent, 'Net::SAML2::SP',
            "Got the correct company name");

        my $display_name
            = get_single_node_ok($xpath, "$p/md:OrganizationDisplayName");
        is(
            $display_name->textContent,
            'Net::SAML2::SP testsuite',
            ".. and the correct display name"
        );

        my $url = get_single_node_ok($xpath, "$p/md:OrganizationURL");
        is($url->textContent, 'http://www.example.com',
            ".. and the correct URI");
    }

    {
        # Test SPSSODescriptor
        my $node = get_single_node_ok($xpath, '/node()/md:SPSSODescriptor');
        is($node->getAttribute('AuthnRequestsSigned'),
            '1', '.. and authn request needs signing');
        is($node->getAttribute('WantAssertionsSigned'),
            '1', '.. as does assertions');
        is($node->getAttribute('errorURL'),
            'http://localhost:3000/error', 'Got the correct error URI');

        my $p = $node->nodePath();

        my $kd = get_single_node_ok($xpath, "$p/md:KeyDescriptor");

        is($kd->getAttribute('use'),
            "signing", "Key descriptor is there for signing only");

        my $ki = get_single_node_ok($xpath, $kd->nodePath() . "/ds:KeyInfo");

        my $cert = get_single_node_ok($xpath,
            $ki->nodePath() . "/ds:X509Data/ds:X509Certificate");
        ok($cert->textContent, "And we have the certificate data");

        my $keyname
            = get_single_node_ok($xpath, $ki->nodePath() . "/ds:KeyName");
        ok($keyname->textContent, "... and we have a key name");
    }

}

{
    # Test Signature
    my $node = get_single_node_ok($xpath, '/node()/ds:Signature');

}

done_testing;
