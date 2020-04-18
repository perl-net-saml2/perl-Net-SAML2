use Test::More;
use strict;
use warnings;
use Net::SAML2;
use MIME::Base64;
use File::Slurp qw( read_file );
use LWP::UserAgent;

my $cert = 't/sign-nopw-cert.pem';
my $key = 't/sign-nopw-cert.pem';
my $cacert = 't/cacert.pem';

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

my $metadata = read_file('t/idp-metadata.xml');
ok($metadata);

my $idp = Net::SAML2::IdP->new_from_xml( xml => $metadata, cacert => 't/cacert.pem' );
ok($idp);

my $slo_url = $idp->slo_url($idp->binding('soap'));
ok($slo_url);
my $idp_cert = $idp->cert('signing');
ok($idp_cert);

my $nameid = 'user-to-log-out';
my $session = 'session-to-log-out';

my $request = $sp->logout_request(
        $idp->entityid, $nameid, $idp->format('persistent'), $session,
);
ok($request);
my $request_xml = $request->as_xml;
ok($request_xml);

my $ua = LWP::UserAgent->new; # not used
my $soap = $sp->soap_binding($ua, $slo_url, $idp_cert);
ok($soap);

my $soap_req = $soap->create_soap_envelope($request_xml);
ok($soap_req);

my ($subject, $xml) = $soap->handle_request($soap_req);
ok($subject);
ok($xml);

my $soaped_request = Net::SAML2::Protocol::LogoutRequest->new_from_xml(
        xml => $xml
);
ok($soaped_request);
isa_ok($soaped_request, 'Net::SAML2::Protocol::LogoutRequest');
ok($soaped_request->session eq $request->session);
ok($soaped_request->nameid eq $request->nameid);

# Repeat Tests for certs as strings

my $cert_text = read_file($cert);
my $key_text = read_file($key);
my $cacert_text = read_file($cacert);

my $sp_text = Net::SAML2::SP->new(
        id               => 'http://localhost:3000',
        url              => 'http://localhost:3000',
        cert             => $cert,
        key              => $key,
        cacert           => $cacert,
        org_name         => 'Test',
        org_display_name => 'Test',
        org_contact      => 'test@example.com',
);
ok($sp_text);

$metadata = read_file('t/idp-metadata.xml');
ok($metadata);

my $idp_text = Net::SAML2::IdP->new_from_xml(
                    xml             => $metadata,
                    cacert          => $cacert_text,
                    certs_as_string => 1 );
ok($idp_text);

my $slo_url_text = $idp->slo_url($idp_text->binding('soap'));
ok($slo_url_text);
my $idp_cert_text = $idp_text->cert('signing');
ok($idp_cert_text);

$nameid = 'user-to-log-out';
$session = 'session-to-log-out';

my $request_text = $sp_text->logout_request(
        $idp_text->entityid, $nameid, $idp_text->format('persistent'), $session,
);
ok($request_text);
my $request_xml_text = $request_text->as_xml;
ok($request_xml_text);

my $soap_text = $sp_text->soap_binding($ua, $slo_url_text, $idp_cert_text);
ok($soap_text);

my $soap_req_text = $soap_text->create_soap_envelope($request_xml_text);
ok($soap_req_text);

my ($subject_text, $xml_text) = $soap_text->handle_request($soap_req_text);
ok($subject_text);
ok($xml_text);

my $soaped_request_text = Net::SAML2::Protocol::LogoutRequest->new_from_xml(
        xml => $xml_text
);
ok($soaped_request_text);
isa_ok($soaped_request_text, 'Net::SAML2::Protocol::LogoutRequest');
ok($soaped_request_text->session eq $request_text->session);
ok($soaped_request_text->nameid eq $request_text->nameid);

done_testing;
