use Test::More;
use Net::SAML2;
use File::Slurp;

my $cacert = 't/cacert.pem';

my $xml = read_file('t/idp-metadata2.xml');

my $idp = Net::SAML2::IdP->new_from_xml( xml => $xml, cacert => $cacert );
ok($idp);

ok($idp->sso_url($idp->binding('redirect')));
ok($idp->slo_url($idp->binding('redirect')));
ok($idp->art_url($idp->binding('soap')));

ok($idp->cert('signing'));
ok($idp->entityid eq 'http://sso.dev.venda.com/opensso');

# Repeat Tests for certs as strings

my $cacert_text = read_file($cacert);

my $idp_text = Net::SAML2::IdP->new_from_xml(
                    xml => $xml,
                    cacert => $cacert_text,
                    certs_as_string => 1);
ok($idp_text);

ok($idp_text->sso_url($idp_text->binding('redirect')));
ok($idp_text->slo_url($idp_text->binding('redirect')));
ok($idp_text->art_url($idp_text->binding('soap')));

ok($idp_text->cert('signing'));
ok($idp_text->entityid eq 'http://sso.dev.venda.com/opensso');

done_testing;
