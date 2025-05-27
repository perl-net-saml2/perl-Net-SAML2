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

our $VERSION = '0.3';

sub load_config {
    my $idp = shift;

    config->{cacert} = 'IdPs/' . $idp . '/cacert.pem';
    config->{idp} = 'http://localhost:8880/IdPs/' . $idp . '/metadata.xml';
    config->{idp_name} = $idp;
    if ( -f 'IdPs/' . $idp . '/config.yml' ) {
        my $config_file = YAML::LoadFile('IdPs/' . $idp . '/config.yml');
        for my $key (keys %$config_file) {
            config->{$key} = $config_file->{$key};
        }
    } else {
        my $config_file = YAML::LoadFile('config.yml');
        for my $key (keys %$config_file) {
            config->{$key} = $config_file->{$key};
        }
    }
};

sub load_idps {
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

    return @idps;
}

get '/' => sub {
    my @idps = load_idps();

    template 'index', {
                        'idps' => \@idps,
                        'sign_metadata' => config->{sign_metadata},
                        'set_idp' => \&set_idp,
                        'get_sso_post_url' => \&get_sso_post_url,
                        'get_login_post' => \&get_login_post,
                    };
};

sub set_idp {
    my $idp = shift;

    config->{cacert} = 'IdPs/' . $idp . '/cacert.pem';
    config->{idp} = 'http://localhost:8880/IdPs/' . $idp . '/metadata.xml';
}

sub get_slo_post_url {
    my $idp_name = shift;

    load_config($idp_name);
    my $idp = _idp();

    return $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
}

sub get_sso_post_url {
    my $idp_name = shift;

    load_config($idp_name);
    my $idp = _idp();

    if ( ! defined $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') ) {
        return "NotSupported";
    }

    return $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
}

sub get_login_post {
    my $idp_name = shift;

    load_config($idp_name);

    my $idp = _idp();
    if ( ! defined $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') ) {
        return "NotSupported";
    }
    my $sp  = _sp();

    my %params = (
        defined (config->{acs_url_in_request}) and (config->{acs_url_in_request} eq 1) ?
            (assertion_url => config->{url} . config->{acs_url_post}) : (),
        defined (config->{force_authn}) ? (force_authn => config->{force_authn}) : (),
        defined (config->{is_passive}) ? (is_passive  => config->{is_passive}) : (),
    );

    config->{slo_urls} = $idp->slo_urls();

    my $authnreq = $sp->authn_request(
        $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
        $idp->format || '', # default format.
        %params,
    )->as_xml;

    my $post = $sp->sp_post_binding($idp, 'SAMLRequest');

    return $post->sign_xml($authnreq);
};

sub get_logout_post {
    my $idp_name        = shift;
    my $nameid          = shift;
    my $session         = shift;
    my $name_qualifier  = shift;
    my $sp_name_qualifier = shift;

    load_config($idp_name);
    my $idp = _idp();
    if ( ! defined $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') ) {
        return "NotSupported";
    }
    my $sp  = _sp();

    my %logout_params = (
                            $name_qualifier ?
                            ( name_qualifier => $name_qualifier) :
                            (),
                            $sp_name_qualifier ?
                            (sp_name_qualifier => $sp_name_qualifier) :
                            (),
                         );

    my $logoutreq = $sp->logout_request(
        $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
        $nameid,
        $idp->format || undef,
        $session,
        \%logout_params,
    )->as_xml;

    my $post = $sp->sp_post_binding($idp, 'SAMLRequest');

    return $post->sign_xml($logoutreq);
};

get '/login' => sub {

    load_config(params->{idp});

    print STDERR "Testing login via redirect: " , config->{idp_name} ,"\n";
    my $idp = _idp();
    my $sp = _sp();

    my %params = (
        defined (config->{acs_url_in_request}) and (config->{acs_url_in_request} eq 1) ?
            (assertion_url => config->{url} . config->{acs_url_post}) : (),
        defined (config->{force_authn}) ? (force_authn => config->{force_authn}) : (),
        defined (config->{is_passive}) ? (is_passive  => config->{is_passive}) : (),
    );

    config->{slo_urls} = $idp->slo_urls();

    my $authnreq = $sp->authn_request(
        $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        $idp->format || '', # default format.
        %params,
    )->as_xml;

    my $redirect = $sp->sso_redirect_binding($idp, 'SAMLRequest');
    my $url = $redirect->sign($authnreq, config->{idp_name});
    redirect $url, 302;

    return "Redirected\n";
};

get '/logout-local' => sub {
    redirect '/?logout=local', 302;
};

get '/logout-redirect' => sub {
    my $idp = _idp();
    my $sp = _sp();

    if ( ! defined $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect') ) {
        redirect "/", 302;
        return; # "Redirected\n";
    }

    my %logout_params = (
                            params->{name_qualifier} ?
                            ( name_qualifier => params->{name_qualifier}) :
                            (),
                            params->{sp_name_qualifier} ?
                            (sp_name_qualifier => params->{sp_name_qualifier}) :
                            (),
                         );

    my $logoutreq = $sp->logout_request(
        $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        params->{nameid},
        $idp->format || undef,
        params->{session},
        \%logout_params,
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

    my %logout_params = (
                            params->{name_qualifier} ?
                            ( name_qualifier => params->{name_qualifier}) :
                            (),
                            params->{sp_name_qualifier} ?
                            (sp_name_qualifier => params->{sp_name_qualifier}) :
                            (),
                         );

    my $logoutreq = $sp->logout_request(
        $slo_url, params->{nameid}, $idp->format || undef, params->{session},
        \%logout_params
    )->as_xml;

    my $ua = LWP::UserAgent->new;

    require LWP::Protocol::https;
    $ua->ssl_opts( (
                        SSL_verify_mode => config->{ssl_verify_hostname},
                        verify_hostname => config->{ssl_verify_hostname},
                    ));

    my $soap = Net::SAML2::Binding::SOAP->new(
        ua          => $ua,
        key         => config->{key},
        cert        => config->{cert},
        url         => $slo_url,
        idp_cert    => $idp_cert,
        cacert      => config->{cacert},
    );

    my $res = $soap->request($logoutreq);

    if ($res) {
        my $logout = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
            xml => $res
        );
        if ($logout->success) {
            print STDERR "        Logout Success Status - $logout->{issuer}\n";
        }
    }
    else {
        return "<html><pre>Bad Logout Response</pre></html>";
    }

    redirect '/?logout=SOAP', 302;
    return "Redirected\n";
};

post '/consumer-post' => sub {
    my $cacert;

    my $relay_state = params->{RelayState} // '';

    my $idp_name;
    if ($relay_state ne '' and defined $relay_state) {
        $idp_name = $relay_state;
        $cacert = 'IdPs/' . $idp_name . '/cacert.pem';
    } else {
        $idp_name = config->{idp_name};
        $cacert = config->{cacert};
    }

    load_config($idp_name);
    config->{idp} = 'http://localhost:8880/IdPs/' . $idp_name . '/metadata.xml';
    my $idp = _idp();

    my $post = Net::SAML2::Binding::POST->new(
        cacert => $cacert,
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

        if (! $assertion->valid(config->{issuer})) {
            return '<html><pre>Bad Assertion</pre></html>';
        }

        my $name_qualifier      = $assertion->nameid_name_qualifier();
        my $sp_name_qualifier   = $assertion->nameid_sp_name_qualifier();

        my $slo_urls = $idp->slo_urls;

        my $user_attributes = get_user_attributes($assertion);

        print STDERR "    Successful login assertion received via POST\n";
        template 'user', {
                            user_attributes => $user_attributes,
                            (defined $name_qualifier ? (name_qualifier => $name_qualifier) : ()),
                            (defined $sp_name_qualifier ? (sp_name_qualifier => $sp_name_qualifier) : ()),
                            (defined $slo_urls ? (slo_urls => $slo_urls) : ()),
                            (defined $idp_name ? (idp_name => $idp_name) : ()),
                            'get_slo_post_url' => \&get_slo_post_url,
                            'get_logout_post' => \&get_logout_post,
                            message => 'Successful Login via POST',
                         };
    }
    else {
        return "<html><pre>Bad Assertion</pre></html>";
    }
};

sub get_attribute_map {

    my $attribute_mappings;

    my $file = 'IdPs/' . config->{idp_name} . '/mappings.yml';

    if ( -e $file ) {
        $attribute_mappings = YAML::LoadFile($file);
    } else {

        $attribute_mappings->{EmailAddress} = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
        $attribute_mappings->{FirstName} = 'fname';
        $attribute_mappings->{LastName} = 'lname';
        $attribute_mappings->{Address} = 'Address';
        $attribute_mappings->{PhoneNumber} = 'PhoneNumber';
        $attribute_mappings->{EmployeeNumber} = 'EmployeeNumber';
    }

    return $attribute_mappings;
}

sub get_user_attributes {
    my $assertion = shift;

    my %user;

    my $map = get_attribute_map();
    $user{issuer} = $assertion->{issuer};
    $user{session} = $assertion->{session};
    $user{nameid} = $assertion->nameid();
    $user{EmailAddress} = $assertion->{attributes}{$map->{EmailAddress}}[0];
    $user{FirstName} = $assertion->{attributes}{$map->{FirstName}}[0];
    $user{LastName} = $assertion->{attributes}{$map->{LastName}}[0];
    $user{Address} = $assertion->{attributes}{$map->{Address}}[0];
    $user{PhoneNumber} = $assertion->{attributes}{$map->{PhoneNumber}}[0];
    $user{EmployeeNumber} = $assertion->{attributes}{$map->{EmployeeNumber}}[0];

    return \%user;
}

any '/consumer-artifact' => sub {
    my $cacert;

    my $relay_state = params->{RelayState} // '';

    my $idp_name;
    if ($relay_state ne '') {
        $idp_name = $relay_state;
        $cacert = 'IdPs/' . $idp_name . '/cacert.pem';
    } else {
        $idp_name = config->{idp_name};
        $cacert = config->{cacert};
    }

    load_config($idp_name);
    config->{idp} = 'http://localhost:8880/IdPs/' . $idp_name . '/metadata.xml';
    my $idp = _idp();

    my $idp_cert = $idp->cert('signing');
    my $art_url  = $idp->art_url('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');

    my $artifact = params->{SAMLart};

    my $sp = _sp();
    my $request = $sp->artifact_request($art_url, $artifact)->as_xml;

    my $ua = LWP::UserAgent->new;

    require LWP::Protocol::https;
    $ua->ssl_opts( (
                        SSL_verify_mode => config->{ssl_verify_hostname},
                        verify_hostname => config->{ssl_verify_hostname},
                    ));

    my $soap = Net::SAML2::Binding::SOAP->new(
        ua          => $ua,
        url         => $art_url,
        key         => config->{key},
        cert        => config->{cert},
        idp_cert    => $idp_cert,
    );

    my $soap_response = $soap->request($request);

    $artifact = Net::SAML2::Protocol::Artifact->new_from_xml(
            xml => $soap_response );

    if ($artifact->success) {
        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
            key_file => config->{key},
            xml => $artifact->get_response(),
        );

        if ( ! $assertion->valid(config->{issuer})) {
            return '<html><pre>Bad Assertion</pre></html>';
        }

        my $name_qualifier      = $assertion->nameid_name_qualifier();
        my $sp_name_qualifier   = $assertion->nameid_sp_name_qualifier();

        my $slo_urls = $idp->slo_urls;

        my $user_attributes = get_user_attributes($assertion);

        print STDERR "    Successful login assertion received via SOAP\n";
        template 'user', {
                            user_attributes => $user_attributes,
                            (defined $name_qualifier ? (name_qualifier => $name_qualifier) : ()),
                            (defined $sp_name_qualifier ? (sp_name_qualifier => $sp_name_qualifier) : ()),
                            (defined $slo_urls ? (slo_urls => $slo_urls) : ()),
                            (defined $idp_name ? (idp_name => $idp_name) : ()),
                            'get_slo_post_url' => \&get_slo_post_url,
                            'get_logout_post' => \&get_logout_post,
                            message => 'Successful Login via SOAP',
                         };
    }
    else {
        return "<html><pre>Bad Artifact Response</pre></html>";
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
        if ($logout->success) {
            print STDERR "        Logout Success Status - $logout->{issuer} via Redirect\n";
        }
    }
    else {
        return "<html><pre>Bad Logout Response</pre></html>";
    }
    redirect '/?logout=redirect', 302;
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
        if ($logout->success) {
            print STDERR "        Logout Success Status - $logout->{issuer} via POST\n";
        }
    }
    else {
        return "<html><pre>Bad Logout Response</pre></html>";
    }

    redirect "/?logout=POST", 302;
    return "Redirected\n";
};

any '/sls-consumer-artifact' => sub {
    my $cacert;

    my $relay_state = params->{RelayState} // '';

    my $idp_name;
    if ($relay_state ne '') {
        $idp_name = $relay_state;
        $cacert = 'IdPs/' . $idp_name . '/cacert.pem';
    } else {
        $idp_name = config->{idp_name};
        $cacert = config->{cacert};
    }

    load_config($idp_name);
    config->{idp} = 'http://localhost:8880/IdPs/' . $idp_name . '/metadata.xml';
    my $idp = _idp();
    my $idp_cert = $idp->cert('signing');
    my $art_url  = $idp->art_url('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');

    my $artifact = params->{SAMLart};

    my $sp = _sp();
    my $request = $sp->artifact_request($art_url, $artifact)->as_xml;

    my $ua = LWP::UserAgent->new;

    require LWP::Protocol::https;
    $ua->ssl_opts( (
                        SSL_verify_mode => config->{ssl_verify_hostname},
                        verify_hostname => config->{ssl_verify_hostname},
                    ));

    my $soap = Net::SAML2::Binding::SOAP->new(
        ua       => $ua,
        url      => $art_url,
        key      => config->{key},
        cert     => config->{cert},
        idp_cert => $idp_cert,
    );

    my $soap_response = $soap->request($request);

    $artifact = Net::SAML2::Protocol::Artifact->new_from_xml(
            xml => $soap_response );

    if ($artifact->success) {
        my $logout = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
            xml => $artifact->get_response(),
        );

        if ($logout->success) {
            print STDERR "        Logout Success Status - $logout->{issuer} - via SOAP\n";
        }
    }
    else {
        return "<html><pre>Bad Artifact Response</pre></html>";
    }

    redirect "/?logout=SOAP-ARTIFACT", 302;
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
        issuer => config->{issuer},
        url    => config->{url},
        cert   => config->{cert},
        key    => config->{key},
        config->{encryption_key} ? (encryption_key => config->{encryption_key}) : (),
        cacert => config->{cacert} || '',
        single_logout_service => [
        {
            Binding => BINDING_HTTP_REDIRECT,
            Location => config->{url} . config->{slo_url_redirect},
        },
        {
            Binding => BINDING_HTTP_POST,
            Location => config->{url} . config->{slo_url_post},
        },
        {
            Binding => BINDING_HTTP_ARTIFACT,
            Location => config->{url} . config->{slo_url_soap},
        }],
        assertion_consumer_service => [
        {
            Binding => BINDING_HTTP_POST,
            Location => config->{url} . config->{acs_url_post},
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
