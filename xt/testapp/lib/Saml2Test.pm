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
use URI::Encode qw(uri_encode uri_decode);

our $VERSION = '0.1';

get '/' => sub {
    template 'index';
};

get '/login' => sub {
    my $idp = _idp();
    my $sp = _sp();
    my $authnreq = $sp->authn_request(
        $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        $idp->format, # default format.
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
        $idp->format,
        params->{session}
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
        key	 => 'sign-nopw-cert.pem',
        cert	 => 'sign-nopw-cert.pem',
        url	 => $slo_url,
        idp_cert => $idp_cert,
        cacert   => 'saml_cacert.pem',
    );

    my $res = $soap->request($logoutreq);

    redirect '/', 302;
    return "Redirected\n";
};

post '/consumer-post' => sub {
    my $post = Net::SAML2::Binding::POST->new(
        cacert => 'saml_cacert.pem',
    );
    my $ret = $post->handle_response(
        params->{SAMLResponse}
    );

    if ($ret) {
        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
            xml => decode_base64(params->{SAMLResponse})
        );

        template 'user', { assertion => $assertion };
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
    my $request = $sp->artifact_request($idp->entityid, $artifact)->as_xml;

    my $soap = Net::SAML2::Binding::SOAP->new(
        url	 => $art_url,
        key	 => 'sign-private.pem',
        cert	 => 'sign-certonly.pem',
        idp_cert => $idp_cert
    );
    my $response = $soap->request($request);

    if ($response) {
        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
            xml => $response
        );

        template 'user', { assertion => $assertion };
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

    my $decoded = uri_decode(request->uri);

    my ($response, $relaystate) = $redirect->verify($decoded);

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
            print STDERR "Logout Success Status\n";
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
    return $sp->metadata;
};

sub _sp {
    my $sp = Net::SAML2::SP->new(
        id     => config->{issuer},
        url    => config->{url},
        cert   => config->{cert},
        key    => config->{key},
        cacert => config->{cacert},
        slo_url_soap => config->{slo_url_soap},
        slo_url_redirect => config->{slo_url_redirect},
        slo_url_post => config->{slo_url_post},
        acs_url_post => config->{acs_url_post},
        acs_url_artifact => config->{acs_url_artifact},
        error_url => config->{error_url},
		
        org_name	 => config->{org_name},
        org_display_name => config->{org_display_name},
        org_contact	 => config->{org_contact},
    );
    return $sp;
}	

sub _idp {
    my $idp = Net::SAML2::IdP->new_from_url(
        url    => config->{idp},
        cacert => 'saml_cacert.pem'
    );
    return $idp;
}

true;
