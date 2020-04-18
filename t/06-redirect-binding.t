use Test::More;
use strict;
use warnings;
use Net::SAML2;
use MIME::Base64;
use Data::Dumper;
use File::Slurp qw(read_file );
use LWP::UserAgent;

my $key = 't/sign-nopw-cert.pem';
my $cert = 't/sign-nopw-cert.pem';
my $cacert = 't/cacert.pem';

my $sp = Net::SAML2::SP->new(
        id               => 'http://localhost:3000',
        url              => 'http://localhost:3000',
        key              => $key,
        cert             => $cert,
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

my $sso_url = $idp->sso_url($idp->binding('redirect'));
ok($sso_url);

my $authnreq = $sp->authn_request(
    $idp->entityid,
    $idp->format('persistent'),
)->as_xml;
ok($authnreq);

my $redirect = $sp->sso_redirect_binding($idp, 'SAMLRequest');
ok($redirect);

my $location = $redirect->sign(
        $authnreq,
        'http://return/url',
);
ok($location);

my ($request, $relaystate) = $redirect->verify($location);
ok($request);
ok($relaystate);
ok($relaystate eq 'http://return/url');

# Repeat tests for certs as strings
my $cert_text = read_file($cert);
my $key_text = read_file($key);
my $cacert_text = read_file($cacert);

my $sp_text = Net::SAML2::SP->new(
        id               => 'http://localhost:3000',
        url              => 'http://localhost:3000',
        key              => $key_text,
        cert             => $cert_text,
        cacert           => $cacert_text,
        org_name         => 'Test',
        org_display_name => 'Test',
        org_contact      => 'test@example.com',
        certs_as_string  => 1,
);
ok($sp_text);

my $metadata_text = read_file('t/idp-metadata.xml');
ok($metadata_text);
my $idp_text = Net::SAML2::IdP->new_from_xml(
                    xml => $metadata,
                    cacert => $cacert_text,
                    certs_as_string => 1 );
ok($idp_text);

my $sso_url_text = $idp_text->sso_url($idp_text->binding('redirect'));
ok($sso_url_text);

my $authnreq_text = $sp_text->authn_request(
    $idp_text->entityid,
    $idp_text->format('persistent'),
)->as_xml;
ok($authnreq_text);

my $redirect_text = $sp_text->sso_redirect_binding($idp_text, 'SAMLRequest');
ok($redirect_text);

my $location_text = $redirect_text->sign(
        $authnreq_text,
        'http://return/url',
);
ok($location_text);

my ($request_text, $relaystate_text) = $redirect_text->verify($location_text);
ok($request_text);
ok($relaystate_text);
ok($relaystate_text eq 'http://return/url');

done_testing;
