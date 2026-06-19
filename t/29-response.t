use strict;
use warnings;
use Test::Lib;
use Test::Net::SAML2;

use Net::SAML2::Object::Response;
use URN::OASIS::SAML2 qw(STATUS_RESPONDER STATUS_AUTH_FAILED);

sub get_object {
  my $xml = path(shift)->slurp;
  my $destination = shift;
  my $response = Net::SAML2::Object::Response->new_from_xml(xml => $xml,
                    cacert  => 't/net-saml2-cacert.pem',
                    require_signed_response => 1,
                    defined $destination ? (destination => $destination) : (),
                );
  isa_ok($response, 'Net::SAML2::Object::Response');
  return $response;
}

{
  my $response = get_object('t/data/digid-anul-artifact-response.xml');
  ok(!$response->has_assertions, "We don't have an assertion");
  ok(!$response->success, "Unsuccessful response");
  is($response->status, STATUS_RESPONDER(), "... because its a status:Responder");
  is($response->substatus, STATUS_AUTH_FAILED(), "... and substatus is also correct");
}


{
  throws_ok(sub{get_object('t/data/eherkenning-assertion.xml', 'INCORRECT_DESTINATION');},
      qr/Response Destination \(https:\/\/test.zaaksysteem.nl\/auth\/saml\/consumer-post\) does not match expected value \(INCORRECT_DESTINATION\)/, "Incorrect Destination fails as expected");
  lives_ok(sub{get_object('t/data/eherkenning-assertion.xml', 'https://test.zaaksysteem.nl/auth/saml/consumer-post');},
      "correct Destination lives as expected");
  my $response = get_object('t/data/eherkenning-assertion.xml');
  ok($response->has_assertions, "We have an assertion");
  ok($response->success, "It was successful");
  is($response->assertions->size, 3, "Got the correct amount or assertions");

  my $assertion = $response->to_assertion(cacert  => 't/net-saml2-cacert.pem');
  isa_ok($assertion, "Net::SAML2::Protocol::Assertion");
}


{
  throws_ok(sub{get_object('t/data/response-no-assertion.xml', 'INCORRECT_DESTINATION');},
      qr/Response Destination \(\[our SAML callback url\]\) does not match expected value \(INCORRECT_DESTINATION\)/, "Incorrect Destination fails as expected");
  my $response = get_object('t/data/response-no-assertion.xml', '[our SAML callback url]');
  ok(!$response->has_assertions, "We don't have an assertion");
  ok(!$response->success, "Unsuccessful response");
  is($response->status, STATUS_RESPONDER(), "... because its a status:Responder");
}

# require_signed_response handling (B2/B3)
{
  # The default (argument omitted) is currently 0 - unsigned and
  # Assertion-only-signed Responses are accepted.
  my $response = Net::SAML2::Object::Response->new_from_xml(
      xml    => path('t/data/eherkenning-assertion.xml')->slurp,
      cacert => 't/net-saml2-cacert.pem',
  );
  isa_ok($response, 'Net::SAML2::Object::Response',
      'default require_signed_response accepts a Response-level-signed response');
  is($response->require_signed_response, 0,
      'require_signed_response attribute defaults to 0');

  # An Assertion-only-signed response (no Response-level Signature) is
  # accepted by default ...
  lives_ok(sub {
      Net::SAML2::Object::Response->new_from_xml(
          xml    => path('t/data/saml-adfs-plain.xml')->slurp,
          cacert => 't/net-saml2-cacert.pem',
      );
      },
      'default require_signed_response accepts an Assertion-only-signed response');

  # ... but require_signed_response => 1 enforces a single Response-level
  # Signature and rejects an Assertion-only-signed response.
  throws_ok(sub {
      Net::SAML2::Object::Response->new_from_xml(
          xml                     => path('t/data/saml-adfs-plain.xml')->slurp,
          cacert                  => 't/net-saml2-cacert.pem',
          require_signed_response => 1,
      );
      },
      qr/include exactly one Signature/,
      'require_signed_response => 1 rejects an Assertion-only-signed response');

  # require_signed_response => 1 accepts a Response that carries exactly one
  # Response-level Signature.
  my $signed = Net::SAML2::Object::Response->new_from_xml(
      xml                     => path('t/data/eherkenning-assertion.xml')->slurp,
      cacert                  => 't/net-saml2-cacert.pem',
      require_signed_response => 1,
  );
  isa_ok($signed, 'Net::SAML2::Object::Response',
      'require_signed_response => 1 accepts a Response-level-signed response');
  is($signed->require_signed_response, 1,
      'require_signed_response => 1 is reflected on the object');
}
done_testing;
