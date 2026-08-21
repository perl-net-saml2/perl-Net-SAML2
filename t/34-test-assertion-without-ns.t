use Test::Lib;
use Test::Net::SAML2;

use POSIX qw(strftime);
use XML::Sig;
use Net::SAML2::Protocol::Assertion;

my $key     = 't/net-saml2-key.pem';
my $cert    = 't/net-saml2-cert.pem';
my $crt_pem = path($cert)->slurp;

my $now = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(time - 60));
my $exp = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(time + 3600));

# Builds a signed Response wrapping an Assertion. When $strip_ns is true,
# the local xmlns:saml declaration on the Assertion element is removed
# (it is redundant since the wrapping Response always declares it).
sub build_response {
    my $strip_ns = shift;

    my $assertion_xml = qq{<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_assertion123" Version="2.0" IssueInstant="$now">
  <saml:Issuer>http://idp.test/idp</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user\@example.com</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="$exp" Recipient="http://sp.test/saml/post"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="$now" NotOnOrAfter="$exp">
    <saml:AudienceRestriction><saml:Audience>http://sp.test</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="$now" SessionIndex="_sess1">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>};

    # Sign it (schema-compliant position: Signature right after Issuer)...
    my $signer = XML::Sig->new({ x509 => 1, key => $key, cert => $cert, no_xml_declaration => 1 });
    my $signed = $signer->sign($assertion_xml);
    my ($sig) = $signed =~ m{(<(?:ds|dsig):Signature\b.*?</(?:ds|dsig):Signature>)}s;
    $signed =~ s{\Q$sig\E}{}s;
    $signed =~ s{(</saml:Issuer>)}{$1$sig}s;

    if ($strip_ns) {
        $signed =~ s/(<saml:Assertion)\s+xmlns:saml="urn:oasis:names:tc:SAML:2\.0:assertion"/$1/;
    }

    return qq{<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp1" Version="2.0" IssueInstant="$now"
                InResponseTo="_authnreq1" Destination="http://sp.test/saml/post">
  <saml:Issuer>http://idp.test/idp</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
$signed
</samlp:Response>};
}

subtest "Assertion with its own xmlns:saml declaration" => sub {
    my $response  = build_response(0);
    my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
        xml       => $response,
        cert_text => $crt_pem,
    );

    isa_ok($assertion, 'Net::SAML2::Protocol::Assertion');
    is($assertion->nameid, 'user@example.com',
        "Assertion with a local xmlns:saml declaration verifies");
};

subtest "Assertion without its own xmlns:saml declaration" => sub {
    my $response  = build_response(1);
    my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
        xml       => $response,
        cert_text => $crt_pem,
    );

    isa_ok($assertion, 'Net::SAML2::Protocol::Assertion');
    is($assertion->nameid, 'user@example.com',
        "Assertion without a local xmlns:saml declaration still verifies");
};

done_testing;
