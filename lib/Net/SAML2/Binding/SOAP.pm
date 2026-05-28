package Net::SAML2::Binding::SOAP;
use Moose;

extends 'Net::SAML2::Binding';

# VERSION

use Carp                  qw/croak confess/;
use MooseX::Types::URI    qw/Uri/;
use LWP::UserAgent        ();
use Net::SAML2::XML::Sig  ();
use Net::SAML2::Util      qw/xml_without_comments new_xpc/;
use HTTP::Request::Common qw/POST/;
use Try::Tiny;

# ABSTRACT: SOAP binding for SAML

=head1 SYNOPSIS

  my $soap = Net::SAML2::Binding::SOAP->new(
    url      => $idp_url,
    key      => $key,
    cert     => $cert,
    idp_cert => $idp_cert,
  );

  my $response = $soap->request($req);


=head1 DESCRIPTION

Transport SAML2 messages over SOAP.

=head1 METHODS

=head2 my $soap = $class->new(%options)

Returns an instance of the SOAP binding configured for the given IdP
service url.

You can use all options from the base-class L<Net::SAML2::Binding> constructor
C<new()>, and additional C<%options>:

=over 4

=item B<ua> => L<LWP::UserAgent> object

Pass your own, fully prepared, user-agent.  For instance, when you wish to
use https.

You can also build the user agent to your liking when extending this class by
overriding C<build_user_agent>.  Besides, you may also tune the default C<ua> via the 
L<PERL_LWP_SSL_CA_FILE, HTTPS_CA_FILE|https://metacpan.org/pod/LWP::UserAgent#SSL_ca_file-=%3E-$path>,
L<PERL_LWP_SSL_CA_PATH and HTTPS_CA_DIR|https://metacpan.org/pod/LWP::UserAgent#SSL_ca_path-=%3E-$path>
environment variables.

=item B<url> => $url (required)

The service URL, as string or URI object.

=item B<key> => $filename (required)

The key to sign with.

=item B<cert> => $filename (required)

The corresponding certificate.

=item B<idp_cert> => ARRAY-of-??? (required)

The idp's signing certificates.

=back

=cut

has ua       => (isa => 'Object', is => 'ro', lazy => 1, builder => 'build_user_agent');
has url      => (isa =>  Uri,  is => 'ro', required => 1, coerce => 1);
has key      => (isa => 'Str', is => 'ro', required => 1);
has cert     => (isa => 'Str', is => 'ro', required => 1);
has idp_cert => (isa => 'ArrayRef[Str]', is => 'ro', required => 1);
has verify   => (isa => 'HashRef', is => 'ro');

# BUILDARGS

around BUILDARGS => sub {
    my ($orig, $self, %params) = @_;
    if(my $c = $params{idp_cert}) {
        $params{idp_cert} = [ $c ] if ref $c ne 'ARRAY';
    }
    $self->$orig(%params);
};

=head2 build_user_agent

Builder for the user agent (for the C<ua> attribute>).  It should return
a L<LWP::UserAgent> compatible object.

=cut

sub build_user_agent { return LWP::UserAgent->new }

=head2 my $response = $soap->request($message)

Submit the message to the IdP's service.

Returns the Response, or dies if there was an error.

=cut

sub request {
    my ($self, $message) = @_;
    my $request     = $self->create_soap_envelope($message);
    my $soap_action = 'http://www.oasis-open.org/committees/security';

    my $req         = POST $self->url, Content => $request;
    # SOAP actions should be wrapped in double quotes:
    # https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383528
    $req->header('SOAPAction'     => qq{"$soap_action"});
    $req->header('Content-Type'   => 'text/xml');
    $req->header('Content-Length' => length $request);

    my $res = $self->ua->request($req);
    $res->is_success
        or croak sprintf("Unable to perform request: %s (%s)", $res->message, $res->code);

    return $self->handle_response($res->decoded_content);
}

=head2 my $saml = $soap->handle_response($response)

Handle a response from a remote system on the SOAP binding.

Accepts a string containing the complete SOAP response.  Returns
the saml XML on success and croaks on failure.

=cut

sub handle_response {
    my ($self, $response) = @_;

    my $saml   = _get_saml_from_soap($response);
    my $verify = $self->verify;
    my @errors;

    foreach my $cert (@{$self->idp_cert}) {
        my $success = try {
            $self->verify_xml(
                $saml,
                no_xml_declaration => 1,
                cert_text          => $cert,
                $verify ? (
                    ns => { artifact => $verify->{ns} },
                    id_attr => '/artifact:' . $verify->{attr_id},
                ) : (),
            );
            return 1;
        }
        catch { push @errors, $_; return 0; };
        return $saml if $success;
    }

    !@errors
        or croak "Unable to verify XML with the given certificates: " . join(", ", @errors);

    return undef;
}

=head2 my $success = $soap->handle_request($request)

Handle a request from a remote system on the SOAP binding.
Returns true on a success.  Croaks when no certificate was
found.

Accepts a string containing the complete SOAP request.

=cut

sub handle_request {
    my ($self, $request) = @_;

    my $saml = _get_saml_from_soap($request)
        or return;

    my @errors;
    foreach my $cert (@{$self->idp_cert}) {
        my $success = try {
            $self->verify_xml($saml, cert_text => $cert);
            return 1;
        }
        catch { push @errors, $_; return 0; };
        return $saml if $success;
    }

    !@errors
        or croak "Unable to verify XML with the given certificates: ". join(", ", @errors);

    return undef;
}

sub _get_saml_from_soap {
    my $soap = shift;
    my $xpc  = new_xpc xml_without_comments $soap;
    my $saml = $xpc->findnodes('/soap-env:Envelope/soap-env:Body/*')->shift;
    return $saml ? $saml->toString : undef;
}

=head2 my $xml = $soap->create_soap_envelope($message)

Signs and SOAP-wraps the given message.

=cut

sub create_soap_envelope {
    my ($self, $message) = @_;

    # sign the message
    my $signer = Net::SAML2::XML::Sig->new(
        key                => $self->key,
        cert               => $self->cert,
        x509               => 1,
        exclusive          => 1,
        no_xml_declaration => 1,
    );
    my $signed_message = $signer->sign_message($message);

    # test verify
    my $ret = $signer->verify($signed_message)
        or confess "failed to sign soap message correctly";

    return <<"__SOAP";
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>$signed_message</SOAP-ENV:Body></SOAP-ENV:Envelope>
__SOAP
}

__PACKAGE__->meta->make_immutable;
