use strict;
use warnings;
use Test::More;
use Test::Exception;
use Path::Tiny;

# Deliberately load ONLY Net::SAML2::Object::Response and NOT the full
# Net::SAML2 stack (and NOT Test::Net::SAML2, whose Util loads Net::SAML2).
# to_assertion() must work standalone, which requires Object::Response to
# load Net::SAML2::Protocol::Assertion itself.  If that `use` is missing the
# rest of the suite hides it because the test helper pulls in Net::SAML2.
use Net::SAML2::Object::Response;

ok($INC{'Net/SAML2/Protocol/Assertion.pm'},
    'Object::Response loads Net::SAML2::Protocol::Assertion');

my $xml = path('t/data/eherkenning-assertion.xml')->slurp;

# Response built with a trust anchor -> to_assertion inherits it, so the
# caller need not supply cacert a second time and a missing cacert cannot
# silently produce an unverified Assertion.
{
    my $resp = Net::SAML2::Object::Response->new_from_xml(
        xml    => $xml,
        cacert => 't/net-saml2-cacert.pem',
    );
    my $assertion;
    lives_ok(sub { $assertion = $resp->to_assertion },
        'standalone to_assertion() succeeds without re-passing cacert');
    isa_ok($assertion, 'Net::SAML2::Protocol::Assertion');
    is($assertion->cacert, 't/net-saml2-cacert.pem',
        'Assertion inherited the Response cacert');
}

# Response built insecure -> the insecure posture flows through, so the
# Assertion does not croak for a missing cacert it was never going to use.
{
    my $resp = Net::SAML2::Object::Response->new_from_xml(
        xml                          => $xml,
        insecure_trust_embedded_cert => 1,
    );
    my $assertion = $resp->to_assertion;
    is($assertion->insecure_trust_embedded_cert, 1,
        'Assertion inherited the Response insecure_trust_embedded_cert flag');
}

# Caller-supplied args override the inherited defaults: an insecure Response
# can still be upgraded to a real trust anchor at to_assertion time.
{
    my $resp = Net::SAML2::Object::Response->new_from_xml(
        xml                          => $xml,
        insecure_trust_embedded_cert => 1,
    );
    my $assertion = $resp->to_assertion(cacert => 't/net-saml2-cacert.pem');
    is($assertion->cacert, 't/net-saml2-cacert.pem',
        'caller cacert overrides the inherited insecure posture');
}

done_testing;
