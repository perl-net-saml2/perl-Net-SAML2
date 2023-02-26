use strict;
use warnings;
use Test::More;

use Net::SAML2;
use YAML;
use LWP::UserAgent;
use Carp qw(croak);
use Saml2Test;

use File::Slurper qw/read_text/;

# Check that IdPs directory exists

ok ( -d -e 'IdPs', "'IdPs' directory exists");

my @idps = Saml2Test::load_idps;

foreach my $idp (@idps) {
    my $idp_name = $idp->{idp};
    #check that metadata exists
    ok ( -e "IdPs/$idp_name/metadata.xml", "$idp_name metadata.xml exists" );

    # Check that cacert exists
    ok ( -e "IdPs/$idp_name/cacert.pem", "$idp_name cacert.pem exists" );

    # Load the config for Saml2Test
    Saml2Test::load_config($idp_name);

    # Load the IdP from the my $idp = Saml2Test::_idp();
    my $idp = Saml2Test::_idp();
    isa_ok($idp, 'Net::SAML2::IdP');

    my $sp = Saml2Test::_sp();
    isa_ok($sp, 'Net::SAML2::SP');

    # load IdP credentials - this should only be used for usernames
    # and passwords that are public or in test systems you control
    if ( ! -e "IdPs/$idp_name/credentials.yml" ) {
        next;
    }

    ok ( -e "IdPs/$idp_name/credentials.yml", "Found credentials for $idp_name");

    my %params = (
        force_authn => 1,
        is_passive  => 1,
    );

    # initiate Bindings
    foreach my $binding (keys %{$idp->sso_urls}) {
        my $authnreq = $sp->authn_request(
            $idp->sso_url($binding),
            $idp->format || '', # default format.
            %params,
        )->as_xml;
        my $redirect = $sp->sso_redirect_binding($idp, 'SAMLRequest');
        isa_ok($redirect, 'Net::SAML2::Binding::Redirect');
    }
}

done_testing;
