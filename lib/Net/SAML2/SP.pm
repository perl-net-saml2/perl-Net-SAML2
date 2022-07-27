use strict;
use warnings;
package Net::SAML2::SP;
# VERSION

use Moose;

use Carp qw(croak);
use Crypt::OpenSSL::X509;
use Digest::MD5 ();
use MooseX::Types::URI qw/ Uri /;
use Net::SAML2::Binding::POST;
use Net::SAML2::Binding::Redirect;
use Net::SAML2::Binding::SOAP;
use Net::SAML2::Protocol::AuthnRequest;
use Net::SAML2::Protocol::LogoutRequest;
use Net::SAML2::Util ();
use URN::OASIS::SAML2 qw(:bindings :urn);
use XML::Generator;

# ABSTRACT: Net::SAML2::SP - SAML Service Provider object

=head1 SYNOPSIS

  my $sp = Net::SAML2::SP->new(
    id   => 'http://localhost:3000',
    url  => 'http://localhost:3000',
    cert => 'sign-nopw-cert.pem',
    key => 'sign-nopw-key.pem',
  );

=head1 METHODS

=cut


=head2 new( ... )

Constructor. Create an SP object.

Arguments:

=over

=item B<url>

base for all SP service URLs

=item B<id>

SP's identity URI.

=item B<cert>

path to the signing certificate

=item B<key>

path to the private key for the signing certificate

=item B<cacert>

path to the CA certificate for verification

=item B<org_name>

SP organisation name

=item B<org_display_name>

SP organisation display name

=item B<org_contact>

SP contact email address

=item B<org_url>

SP organization url.  This is optional and url will be used as in
previous versions if this is not provided.

=item B<authnreq_signed>

Specifies in the metadata whether the SP signs the AuthnRequest
Optional (0 or 1) defaults to 1 (TRUE) if not specified.

=item B<want_assertions_signed>

Specifies in the metadata whether the SP wants the Assertion from
the IdP to be signed
Optional (0 or 1) defaults to 1 (TRUE) if not specified.

=item B<sign_metadata>

Sign the metadata, defaults to 1 (TRUE) if not specified.

=item B<single_logout_service>

The following option replaces the previous C<slo_url_post>, C<slo_url_soap> and
C<slo_url_redirect> constructor parameters. The former options are mapped to
this new structure.

This expects an array of hash refs where you define one or more Single Logout
Services

  [
    {
        Binding => BINDING_HTTP_POST,
        Location => https://foo.example.com/your-post-endpoint,
    }
    {
        Binding => BINDING_HTTP_ARTIFACT,
        Location => https://foo.example.com/your-artifact-endpoint,
    }
  ]

=item B<assertion_consumer_service>

The following option replaces the previous C<acs_url_post> and
C<acs_url_artifact> constructor parameters. The former options are mapped to
this new structure.

This expects an array of hash refs where you define one or more Assertion
Consumer Services.

  [
    # Order decides the index
    {
        Binding => BINDING_HTTP_POST,
        Location => https://foo.example.com/your-post-endpoint,
        isDefault => 'false',
    }
    {
        Binding => BINDING_HTTP_ARTIFACT,
        Location => https://foo.example.com/your-artifact-endpoint,
        isDefault => 'true',
    }
  ]

=back

=cut

has 'url'    => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'id'     => (isa => 'Str', is => 'ro', required => 1);
has 'cert'   => (isa => 'Str', is => 'ro', required => 1);
has 'key'    => (isa => 'Str', is => 'ro', required => 1);
has 'cacert' => (isa => 'Maybe[Str]', is => 'ro', required => 1);

has 'error_url'        => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'org_name'         => (isa => 'Str', is => 'ro', required => 1);
has 'org_display_name' => (isa => 'Str', is => 'ro', required => 1);
has 'org_contact'      => (isa => 'Str', is => 'ro', required => 1);
has 'org_url'          => (isa => 'Str', is => 'ro', required => 0);

# These are no longer in use, but are not removed by the off change that
# someone that extended us or added a role to us with these params.
has 'slo_url_soap'     => (isa => 'Str', is => 'ro', required => 0);
has 'slo_url_post'     => (isa => 'Str', is => 'ro', required => 0);
has 'slo_url_redirect' => (isa => 'Str', is => 'ro', required => 0);
has 'acs_url_post'     => (isa => 'Str', is => 'ro', required => 0);
has 'acs_url_artifact' => (isa => 'Str', is => 'ro', required => 0);

has '_cert_text' => (isa => 'Str', is => 'ro', init_arg => undef, builder => '_build_cert_text', lazy => 1);

has 'authnreq_signed'         => (isa => 'Bool', is => 'ro', required => 0, default => 1);
has 'want_assertions_signed'  => (isa => 'Bool', is => 'ro', required => 0, default => 1);

has 'sign_metadata' => (isa => 'Bool', is => 'ro', required => 0, default => 1);

has assertion_consumer_service => (is => 'ro', isa => 'ArrayRef', required => 1);
has single_logout_service => (is => 'ro', isa => 'ArrayRef', required => 1);

around BUILDARGS => sub {
    my $orig = shift;
    my $self = shift;

    my %args = @_;

    if (!$args{single_logout_service}) {
        #warn "Deprecation warning, please upgrade your code to use ..";
        my @slo;
        if (my $slo = $args{slo_url_soap}) {
            push(
                @slo,
                {
                    Binding  => BINDING_SOAP,
                    Location => $args{url} . $slo,
                }
            );
        }
        if (my $slo = $args{slo_url_redirect}) {
            push(
                @slo,
                {
                    Binding  => BINDING_HTTP_REDIRECT,
                    Location => $args{url} . $slo,
                }
            );
        }
        if (my $slo = $args{slo_url_post}) {
            push(
                @slo,
                {
                    Binding  => BINDING_HTTP_POST,
                    Location => $args{url} . $slo,
                }
            );
        }
        $args{single_logout_service} = \@slo;
    }

    if (!@{$args{single_logout_service}}) {
      croak("You don't have any Single Logout Services configured!");
    }

    if (!$args{assertion_consumer_service}) {
        #warn "Deprecation warning, please upgrade your code to use ..";
        my @acs;
        if (my $acs = delete $args{acs_url_post}) {
            push(
                @acs,
                {
                    Binding  => BINDING_HTTP_POST,
                    Location => $args{url} . $acs,
                    isDefault => 'true',
                }
            );
        }
        if (my $acs = $args{acs_url_artifact}) {
            push(
                @acs,
                {
                    Binding  => BINDING_HTTP_ARTIFACT,
                    Location => $args{url} . $acs,
                    isDefault => 'false',
                }
            );
        }

        $args{assertion_consumer_service} = \@acs;
    }
    if (!@{$args{assertion_consumer_service}}) {
      croak("You don't have any Assertion Consumer Services configured!");
    }
    return $self->$orig(%args);
};

sub _build_cert_text {
    my ($self) = @_;

    my $cert = Crypt::OpenSSL::X509->new_from_file($self->cert);
    my $text = $cert->as_string;
    $text =~ s/-----[^-]*-----//gm;
    return $text;
}

=head2 authn_request( $destination, $nameid_format )

Returns an AuthnRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

=cut

sub authn_request {
    my ($self, $destination, $nameid_format) = @_;

    my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
        issueinstant  => DateTime->now,
        issuer        => $self->id,
        destination   => $destination,
        nameid_format => $nameid_format,
    );

    return $authnreq;
}

=head2 logout_request( $destination, $nameid, $nameid_format, $session )

Returns a LogoutRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the nameid (+format) and session to be logged out.

=cut

sub logout_request {
    my ($self, $destination, $nameid, $nameid_format, $session) = @_;

    my $logout_req = Net::SAML2::Protocol::LogoutRequest->new(
        issuer        => $self->id,
        destination   => $destination,
        nameid        => $nameid,
        nameid_format => $nameid_format,
        session       => $session,
    );

    return $logout_req;
}

=head2 logout_response( $destination, $status, $response_to )

Returns a LogoutResponse object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the status and the ID of the corresponding
LogoutRequest.

=cut

sub logout_response {
    my ($self, $destination, $status, $response_to) = @_;

    my $status_uri = Net::SAML2::Protocol::LogoutResponse->status_uri($status);
    my $logout_req = Net::SAML2::Protocol::LogoutResponse->new(
        issuer      => $self->id,
        destination => $destination,
        status      => $status_uri,
        response_to => $response_to,
    );

    return $logout_req;
}

=head2 artifact_request( $destination, $artifact )

Returns an ArtifactResolve request object created by this SP, intended
for the given destination, which should be the identity URI of the
IdP.

=cut

sub artifact_request {
    my ($self, $destination, $artifact) = @_;

    my $artifact_request = Net::SAML2::Protocol::ArtifactResolve->new(
        issuer       => $self->id,
        destination  => $destination,
        artifact     => $artifact,
        issueinstant => DateTime->now,
    );

    return $artifact_request;
}

=head2 sso_redirect_binding( $idp, $param )

Returns a Redirect binding object for this SP, configured against the
given IDP for Single Sign On. $param specifies the name of the query
parameter involved - typically C<SAMLRequest>.

=cut

sub sso_redirect_binding {
    my ($self, $idp, $param) = @_;

    my $redirect = Net::SAML2::Binding::Redirect->new(
        url   => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        cert  => $idp->cert('signing'),
        key   => $self->key,
        param => $param,
    );

    return $redirect;
}

=head2 slo_redirect_binding( $idp, $param )

Returns a Redirect binding object for this SP, configured against the
given IDP for Single Log Out. $param specifies the name of the query
parameter involved - typically C<SAMLRequest> or C<SAMLResponse>.

=cut

sub slo_redirect_binding {
    my ($self, $idp, $param) = @_;

    my $redirect = Net::SAML2::Binding::Redirect->new(
        url   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        cert  => $idp->cert('signing'),
        key   => $self->key,
        param => $param,
        sls_force_lcase_url_encoding => $idp->{sls_force_lcase_url_encoding},
        sls_double_encoded_response => $idp->{sls_double_encoded_response},
    );
    return $redirect;
}

=head2 soap_binding( $ua, $idp_url, $idp_cert )

Returns a SOAP binding object for this SP, with a destination of the
given URL and signing certificate.

XXX UA

=cut

sub soap_binding {
    my ($self, $ua, $idp_url, $idp_cert) = @_;

    my $soap = Net::SAML2::Binding::SOAP->new(
        ua       => $ua,
        key      => $self->key,
        cert     => $self->cert,
        url      => $idp_url,
        idp_cert => $idp_cert,
        cacert   => $self->cacert,
    );

    return $soap;
}

=head2 post_binding( )

Returns a POST binding object for this SP.

=cut

sub post_binding {
    my ($self) = @_;

    my $post = Net::SAML2::Binding::POST->new(
        cacert => $self->cacert,
    );

    return $post;
}

=head2 generate_sp_desciptor_id ( )

Returns the Net::SAML2 unique ID from Net::SAML2::Util::generate_id.

=cut

sub generate_sp_desciptor_id {
    my $self = shift;
    return Net::SAML2::Util::generate_id();
}

=head2 generate_metadata( )

Generate the metadata XML document for this SP.

=cut

my $md = ['md' => 'urn:oasis:names:tc:SAML:2.0:metadata'];
my $ds = ['ds' => 'http://www.w3.org/2000/09/xmldsig#'];

sub generate_metadata {
    my $self = shift;

    my $x = XML::Generator->new(':pretty', conformance => 'loose');

    my $error_uri = $self->error_url;
    if (!$error_uri->scheme) {
        $error_uri = $self->url . $self->error_url;
    }

    return $x->EntityDescriptor(
        $md,
        {
            entityID => $self->id,
            ID       => $self->generate_sp_desciptor_id(),
        },
        $x->SPSSODescriptor(
            $md,
            {
                AuthnRequestsSigned        => $self->authnreq_signed,
                WantAssertionsSigned       => $self->want_assertions_signed,
                errorURL                   => $error_uri,
                protocolSupportEnumeration =>
                    'urn:oasis:names:tc:SAML:2.0:protocol',
            },

            $self->_generate_key_descriptors($x),

            $self->_generate_single_logout_service($x),

            $self->_generate_assertion_consumer_service($x),

        ),
        $x->Organization(
            $md,
            $x->OrganizationName(
                $md, { 'xml:lang' => 'en' }, $self->org_name,
            ),
            $x->OrganizationDisplayName(
                $md, { 'xml:lang' => 'en' },
                $self->org_display_name,
            ),
            $x->OrganizationURL(
                $md,
                { 'xml:lang' => 'en' },
                defined($self->org_url) ? $self->org_url : $self->url
            )
        ),
        $x->ContactPerson(
            $md,
            { contactType => 'other' },
            $x->Company($md, $self->org_display_name,),
            $x->EmailAddress($md, $self->org_contact,),
        )
    );
}

sub _generate_key_descriptors {
    my $self = shift;
    my $x    = shift;

    return
           if !$self->authnreq_signed
        && !$self->want_assertions_signed
        && !$self->sign_metadata;

    return $x->KeyDescriptor(
        $md,
        { use => 'signing' },
        $x->KeyInfo(
            $ds,
            $x->X509Data(
                $ds,
                $x->X509Certificate(
                    $ds,
                    $self->_cert_text,
                )
            ),
            $x->KeyName(
                $ds,
                Digest::MD5::md5_hex($self->_cert_text)
            ),

        )
    );
}

sub _generate_single_logout_service {
    my $self = shift;
    my $x    = shift;
    return map { $x->SingleLogoutService($md, $_) } @{ $self->single_logout_service };
}

sub _generate_assertion_consumer_service {
    my $self = shift;
    my $x    = shift;

    my @services = @{ $self->assertion_consumer_service };
    my $size     = @services;

    my @acs;
    for (my $i = 0; $i < $size; ++$i) {
        push(
            @acs,
            $x->AssertionConsumerService(
                $md, { %{ $services[$i] }, index => $i + 1, },
            )
        );
    }
    return @acs;

}


=head2 metadata( )

Returns the metadata XML document for this SP.

=cut

sub metadata {
    my $self = shift;

    my $metadata = $self->generate_metadata();
    return $metadata unless $self->sign_metadata;

    use Net::SAML2::XML::Sig;
    my $signer = Net::SAML2::XML::Sig->new(
        {
            key         => $self->key,
            cert        => $self->cert,
            sig_hash    => 'sha256',
            digest_hash => 'sha256',
            x509        => 1,
            ns          => { md => 'urn:oasis:names:tc:SAML:2.0:metadata' },
            id_attr     => '/md:EntityDescriptor[@ID]',
        }
    );
    return $signer->sign($metadata);
}

__PACKAGE__->meta->make_immutable;
