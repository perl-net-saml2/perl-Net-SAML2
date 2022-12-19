package                         # PAUSE hide
     Saml2Test;
use strict;
use warnings;

=head1 NAME

Saml2Test - test Dancer app for Net::SAML2

=head1 DESCRIPTION

Demo app to show use of Net::SAML2 as an SP.

=cut

use Dancer ':syntax';
use Net::SAML2;
use MIME::Base64 qw/ decode_base64 /;
use File::Slurper qw/ read_dir /;
use URN::OASIS::SAML2 qw(:bindings :urn);

our $VERSION = '0.2';

get '/' => sub {
    if ( ! -x './IdPs' ) {
        return "<html><pre>You must have a xt/testapp/IdPs directory</pre></html>";
    }
    my @dirs = read_dir('./IdPs');
    my @idps;
    for my $dir (sort @dirs) {
        if ( $dir eq '.keep' ) { next ; }
        my %tempidp;
        $tempidp{'idp'} = $dir;
        if ( -f "./IdPs/$dir/cacert.pem" ) {
            $tempidp{'cacert'} = 'exists';
        } else {
            $tempidp{'cacert'} = 'missing';
        }
        if ( -f "./IdPs/$dir/metadata.xml" ) {
            $tempidp{'metadata'} = 'exists';
        } else {
            $tempidp{'metadata'} = 'missing';
        }
        push @idps, \%tempidp;
    }

    template 'index', { 'idps' => \@idps, 'sign_metadata' => config->{sign_metadata} };
};

get '/login' => sub {

    config->{cacert} = 'IdPs/' . params->{idp} . '/cacert.pem';
    config->{idp} = 'http://localhost:8880/IdPs/' . params->{idp} . '/metadata.xml';
    if ( -f 'IdPs/' . params->{idp} . '/config.yml' ) {
        my $config_file = YAML::LoadFile('IdPs/' . params->{idp} . '/config.yml');
        for my $key (keys %$config_file) {
            config->{$key} = $config_file->{$key};
        }
    } else {
        my $config_file = YAML::LoadFile('config.yml');
        for my $key (keys %$config_file) {
            config->{$key} = $config_file->{$key};
        }

    }
    my $idp = _idp();
    my $sp = _sp();

    my %params = (
        defined (config->{force_authn}) ? (force_authn => config->{force_authn}) : (),
        defined (config->{is_passive}) ? (is_passive  => config->{is_passive}) : (),
    );

    my $authnreq = $sp->authn_request(
        $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        $idp->format || '', # default format.
        %params,
    )->as_xml;

    my $redirect = $sp->sso_redirect_binding($idp, 'SAMLRequest');
    my $url = $redirect->sign($authnreq);
    redirect $url, 302;

    return "Redirected\n";
};

get '/logout-local' => sub {
    redirect '/', 302;
};

get '/logout-redirect' => sub {
    my $idp = _idp();
    my $sp = _sp();

    if ( ! defined $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect') ) {
        redirect "/", 302;
        return; # "Redirected\n";
    }

    my $logoutreq = $sp->logout_request(
        $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        params->{nameid},
        $idp->format || undef,
        params->{session},
        params->{name_qualifier} || undef,
        params->{sp_name_qualifier} || undef,
    )->as_xml;

    my $redirect = $sp->slo_redirect_binding($idp, 'SAMLRequest');
    my $url = $redirect->sign($logoutreq);
    redirect $url, 302;

    return "Redirected\n";
};

get '/logout-soap' => sub {
    my $idp = _idp();
    my $slo_url = $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');

    if ( ! defined $slo_url ) {
        redirect "/", 302;
        return "Redirected\n";
    }

    my $idp_cert = $idp->cert('signing');

    my $sp = _sp();
    my $logoutreq = $sp->logout_request(
        $idp->entityid, params->{nameid}, $idp->format, params->{session}
    )->as_xml;

    my $soap = Net::SAML2::Binding::SOAP->new(
        key      => config->{key},
        cert     => config->{cert},
        url      => $slo_url,
        idp_cert => $idp_cert,
        cacert   => config->{cacert},
    );

    my $res = $soap->request($logoutreq);

    redirect '/', 302;
    return "Redirected\n";
};

post '/consumer-post' => sub {
    my $post = Net::SAML2::Binding::POST->new(
        cacert => config->{cacert},
    );
    my $ret = $post->handle_response(
        params->{SAMLResponse}
    );

    if ($ret) {
        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
            xml         => decode_base64(params->{SAMLResponse}),
            key_file    => config->{key},
            cacert      => config->{cacert},
        );

        my $name_qualifier      = $assertion->nameid_name_qualifier();
        my $sp_name_qualifier   = $assertion->nameid_sp_name_qualifier();

        template 'user', {
                            assertion => $assertion,
                            ($name_qualifier ? (name_qualifier => $name_qualifier) : ()),
                            ($sp_name_qualifier ? (sp_name_qualifier => $sp_name_qualifier) : ()),
                         };
    }
    else {
        return "<html><pre>Bad Assertion</pre></html>";
    }
};

get '/consumer-artifact' => sub {
    my $idp = _idp();
    my $idp_cert = $idp->cert('signing');
    my $art_url  = $idp->art_url('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');

    my $artifact = params->{SAMLart};

    my $sp = _sp();
    my $request = $sp->artifact_request($art_url, $artifact)->as_xml;

    my $ua = LWP::UserAgent->new;

    require LWP::Protocol::https;
    $ua->ssl_opts( (verify_hostname => config->{ssl_verify_hostname}));

    my $soap = Net::SAML2::Binding::SOAP->new(
        ua       => $ua,
        url      => $art_url,
        key      => config->{key},
        cert     => config->{cert},
        idp_cert => $idp_cert,
    );

    my $response = $soap->request($request);

    if ($response) {
        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
            xml => $response,
            key_file => config->{key},
        );

        my $name_qualifier      = $assertion->nameid_name_qualifier();
        my $sp_name_qualifier   = $assertion->nameid_sp_name_qualifier();

        template 'user', {
                            assertion => $assertion,
                            ($name_qualifier ? (name_qualifier => $name_qualifier) : ()),
                            ($sp_name_qualifier ? (sp_name_qualifier => $sp_name_qualifier) : ()),
                         };
    }
    else {
        return "<html><pre>Bad Assertion</pre></html>";
    }
};

get '/sls-redirect-response' => sub {
    my $idp = _idp();
    my $idp_cert = $idp->cert('signing');

    my $sp = _sp();
    my $redirect = $sp->slo_redirect_binding($idp, 'SAMLResponse');

    my ($response, $relaystate) = $redirect->verify(request->uri);

    if ($response) {
        my $logout = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
            xml => $response
        );
        if ($logout->status eq 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            print STDERR "\nLogout Success Status - $logout->{issuer}\n";
        }
    }
    else {
        return "<html><pre>Bad Logout Response</pre></html>";
    }
    redirect $relaystate || '/', 302;
    return "Redirected\n";
};

post '/sls-post-response' => sub {
    my $idp = _idp();
    my $idp_cert = $idp->cert('signing');

    my $sp = _sp();
    my $post = $sp->post_binding(cacert => $idp_cert);

    my $ret = $post->handle_response(
        params->{SAMLResponse},
    );

    if ($ret) {
        my $logout = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
            xml => decode_base64(params->{SAMLResponse})
        );
        if ($logout->status eq 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            print STDERR "\nLogout Success Status - $logout->{issuer}\n";
        }
    }
    else {
        return "<html><pre>Bad Logout Response</pre></html>";
    }

    redirect '/', 302;
    return "Redirected\n";
};

get '/metadata.xml' => sub {

    content_type 'application/octet-stream';

    my $sp = _sp();
    if (defined params->{signmetadata} and params->{signmetadata} = 'on') {
        $sp->{sign_metadata} = 1;
    } else {
        $sp->{sign_metadata} = 0;
    }
    return $sp->metadata;
};

sub _sp {
    my $sp = Net::SAML2::SP->new(
        id     => config->{issuer},
        url    => config->{url},
        cert   => config->{cert},
        key    => config->{key},
        config->{encryption_key} ? (encryption_key => config->{encryption_key}) : (),
        cacert => config->{cacert} || '',
        slo_url_soap => config->{slo_url_soap},
        slo_url_redirect => config->{slo_url_redirect},
        slo_url_post => config->{slo_url_post},
        assertion_consumer_service => [
        {
            Binding => BINDING_HTTP_POST,
            Location => config->{url} . config->{slo_url_post},
            isDefault => 'false',
            # optionally
            index => 1,
        },
        {
            Binding => BINDING_HTTP_ARTIFACT,
            Location => config->{url} . config->{acs_url_artifact},
            isDefault => 'true',
            index => 2,
        }],
        error_url => config->{error_url},
		
        org_name	 => config->{org_name},
        org_display_name => config->{org_display_name},
        org_contact	 => config->{org_contact},
        authnreq_signed => config->{authnreq_signed},
    );
    return $sp;
}

sub _idp {
    my $idp = Net::SAML2::IdP->new_from_url(
        url    => config->{idp},
        cacert => config->{cacert},
    );
    return $idp;
}

true;
