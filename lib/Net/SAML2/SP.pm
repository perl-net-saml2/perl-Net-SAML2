use strict;
use warnings;
package Net::SAML2::SP;
# VERSION

use Moose;

use Carp qw(croak);
use Crypt::OpenSSL::X509;
use Digest::MD5 ();
use List::Util qw(first none);
use MooseX::Types::URI qw/ Uri /;
use MooseX::Types::Common::String qw/ NonEmptySimpleStr /;
use Net::SAML2::Binding::POST;
use Net::SAML2::Binding::Redirect;
use Net::SAML2::Binding::SOAP;
use Net::SAML2::Protocol::AuthnRequest;
use Net::SAML2::Protocol::LogoutRequest;
use Net::SAML2::Util ();
use URN::OASIS::SAML2 qw(:bindings :urn);
use XML::Generator;
use Net::SAML2::Types qw(XsdID);

# ABSTRACT: SAML Service Provider object

=head1 SYNOPSIS

my $sp = Net::SAML2::SP->new(
    issuer => 'http://localhost:3000',
    url    => 'http://localhost:3000',
    cert   => 'sign-nopw-cert.pem',
    key    => 'sign-nopw-key.pem',
);

=head1 METHODS

=cut


=head2 new( ... )

Constructor. Create an SP object.

Arguments:

=over

=item B<id>

The ID attribute used in the EntityDescription tag

=item B<url>

Base for all SP service URLs

=item B<error_url>

The error URI. Can be relative to the base URI or a regular URI

=item B<issuer>

SP's identity URI.

=item B<cert>

Path to the signing certificate

=item B<key>

Path to the private key for the signing certificate

=item B<encryption_key>

Path to the public key that the IdP should use for encryption. This
is used when generating the metadata.

=item B<cacert>

Path to the CA certificate for verification

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
    },
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
    # Order decides the index if not supplied, else we assume you have an index
    {
        Binding => BINDING_HTTP_POST,
        Location => https://foo.example.com/your-post-endpoint,
        isDefault => 'false',
        # optionally
        index => 1,
    },
    {
        Binding => BINDING_HTTP_ARTIFACT,
        Location => https://foo.example.com/your-artifact-endpoint,
        isDefault => 'true',
        index => 2,
    }
  ]

=back

=cut

has 'url'    => (isa => Uri, is => 'ro', required => 1, coerce => 1);

has '_id' => (
    isa      => XsdID,
    is       => 'ro',
    builder  => '_build_id',
    init_arg => 'id'
);

has 'issuer' => (isa => 'Str', is => 'ro', required => 1);

has 'cert'   => (isa => 'Str', is => 'ro', required => 1, predicate => 'has_cert');
has 'key'    => (isa => 'Str', is => 'ro', required => 1);
has 'cacert' => (isa => 'Str', is => 'rw', required => 0, predicate => 'has_cacert');

has 'signing_only' => (isa => 'Bool', is => 'ro', required => 0);

has 'encryption_key'   => (isa => 'Str', is => 'ro', required => 0, predicate => 'has_encryption_key');
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

has 'attribute_consuming_service' =>
  (isa => 'Net::SAML2::AttributeConsumingService', is => 'ro', predicate => 'has_attribute_consuming_service');

has '_cert_text' => (isa => 'Str', is => 'ro', init_arg => undef, builder => '_build_cert_text', lazy => 1);

has '_encryption_key_text' => (isa => 'Str', is => 'ro', init_arg => undef, builder => '_build_encryption_key_text', lazy => 1);
has 'authnreq_signed'         => (isa => 'Bool', is => 'ro', required => 0, default => 1);
has 'want_assertions_signed'  => (isa => 'Bool', is => 'ro', required => 0, default => 1);

has 'sign_metadata' => (isa => 'Bool', is => 'ro', required => 0, default => 1);

has assertion_consumer_service => (is => 'ro', isa => 'ArrayRef', required => 1);
has single_logout_service => (is => 'ro', isa => 'ArrayRef', required => 1);

around BUILDARGS => sub {
    my $orig = shift;
    my $self = shift;

    my %args = @_;

    if (!exists $args{issuer} && exists $args{id}) {
      Net::SAML2::Util::deprecation_warning
        "id has been renamed to issuer and should be used instead";
      $args{issuer} = delete $args{id};
    }

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

    my $acs_index = 1;
    if (none { $_->{index} } @{$args{assertion_consumer_service}}) {
        foreach (@{$args{assertion_consumer_service}}) {
            $_->{index} = $acs_index;
            ++$acs_index;
        }
    }

    return $self->$orig(%args);
};

sub _build_id {
    my $self = shift;
    return Net::SAML2::Util::generate_id();
}

sub id {
    my $self = shift;
    Net::SAML2::Util::deprecation_warning
      "id() has been renamed to issuer()";
    return $self->issuer;
}


sub _build_encryption_key_text {
    my ($self) = @_;

    return '' unless $self->has_encryption_key;
    my $cert = Crypt::OpenSSL::X509->new_from_file($self->encryption_key);
    my $text = $cert->as_string;
    $text =~ s/-----[^-]*-----//gm;
    return $text;
}

sub _build_cert_text {
    my ($self) = @_;

    return '' unless $self->has_cert;
    my $cert = Crypt::OpenSSL::X509->new_from_file($self->cert);
    my $text = $cert->as_string;
    $text =~ s/-----[^-]*-----//gm;
    return $text;
}

=head2 authn_request( $destination, $nameid_format, %params )

Returns an AuthnRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

%params is a hash containing parameters valid for
Net::SAML2::Protocol::AuthnRequest.  For example:

=over

my %params = (
        force_authn => 1,
        is_passive  => 1,
    )

my $authnreq = authn_request(
                'https://keycloak.local:8443/realms/Foswiki/protocol/saml',
                'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                %params
            );

=back

=cut

sub authn_request {
    my $self = shift;
    my $destination     = shift;
    my $nameid_format   = shift;
    my (%params)        = @_;

    return Net::SAML2::Protocol::AuthnRequest->new(
        issueinstant        => DateTime->now,
        issuer              => $self->issuer,
        destination         => $destination,
        nameidpolicy_format => $nameid_format || '',
        %params,
    );

}

=head2 logout_request( $destination, $nameid, $nameid_format, $session, $params )

Returns a LogoutRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the nameid (+format) and session to be logged out.

=over

$params is a HASH reference for parameters to Net::SAML2::Protocol::LogoutRequest

$params =   (
                # name qualifier parameters from Assertion NameId
                name_qualifier      => "https://idp.shibboleth.local/idp/shibboleth"
                sp_name_qualifier   => "https://netsaml2-testapp.local"
            );

=back

=cut

sub logout_request {
    my ($self, $destination, $nameid, $nameid_format, $session, $params) = @_;

    my $logout_req = Net::SAML2::Protocol::LogoutRequest->new(
        issuer      => $self->issuer,
        destination => $destination,
        nameid      => $nameid,
        session     => $session,
        NonEmptySimpleStr->check($nameid_format)
            ? (nameid_format => $nameid_format)
            : (),
        (defined $params->{sp_name_qualifier})
            ? (affiliation_group_id => $params->{sp_name_qualifier})
            : (),
        (defined $params->{name_qualifier})
            ? (name_qualifier => $params->{name_qualifier})
            : (),
        (defined $params->{include_name_qualifier})
            ? ( include_name_qualifier => $params->{include_name_qualifier} )
            : ( include_name_qualifier => 1),
    );
    return $logout_req;
}

=head2 logout_response( $destination, $status, $in_response_to )

Returns a LogoutResponse object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the status and the ID of the corresponding
LogoutRequest.

=cut

sub logout_response {
    my ($self, $destination, $status, $in_response_to) = @_;

    my $status_uri = Net::SAML2::Protocol::LogoutResponse->status_uri($status);
    my $logout_req = Net::SAML2::Protocol::LogoutResponse->new(
        issuer          => $self->issuer,
        destination     => $destination,
        status          => $status_uri,
        in_response_to  => $in_response_to,
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
        issuer       => $self->issuer,
        destination  => $destination,
        artifact     => $artifact,
        issueinstant => DateTime->now,
    );

    return $artifact_request;
}

=head2 sp_post_binding ( $idp, $param )

Returns a POST binding object for this SP, configured against the
given IDP for Single Sign On. $param specifies the name of the query
parameter involved - typically C<SAMLRequest>.

=cut

sub sp_post_binding {
    my ($self, $idp, $param) = @_;

    unless ($idp) {
        croak("Unable to create a post binding without an IDP");
    }

    $param //= 'SAMLRequest';

    my $post = Net::SAML2::Binding::POST->new(
        url   => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
        cert  => ($self->cert,),
        $self->authnreq_signed ? (
            key   => $self->key,
        ) : (
            insecure => 1,
        ),
        param => $param,
    );

    return $post;
}

=head2 sso_redirect_binding( $idp, $param )

Returns a Redirect binding object for this SP, configured against the
given IDP for Single Sign On. $param specifies the name of the query
parameter involved - typically C<SAMLRequest>.

=cut

sub sso_redirect_binding {
    my ($self, $idp, $param) = @_;

    unless ($idp) {
        croak("Unable to create a redirect binding without an IDP");
    }

    $param = 'SAMLRequest' unless $param;

    my $redirect = Net::SAML2::Binding::Redirect->new(
        url   => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        cert  => $idp->cert('signing'),
        $self->authnreq_signed ? (
            key   => $self->key,
        ) : (
            insecure => 1,
        ),
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

    return Net::SAML2::Binding::SOAP->new(
        ua       => $ua,
        key      => $self->key,
        cert     => $self->cert,
        url      => $idp_url,
        idp_cert => $idp_cert,
        $self->has_cacert ? (cacert => $self->cacert) : (),
    );
}

=head2 post_binding( )

Returns a POST binding object for this SP.

=cut

sub post_binding {
    my ($self) = @_;

    return Net::SAML2::Binding::POST->new(
        $self->has_cacert ? (cacert => $self->cacert) : ()
    );
}

=head2 generate_metadata( )

Generate the metadata XML document for this SP.

=cut

my $md = ['md' => URN_METADATA];
my $ds = ['ds' => URN_SIGNATURE];

sub generate_metadata {
    my $self = shift;

    my $x = XML::Generator->new(conformance => 'loose', xml => { version => "1.0", encoding => 'UTF-8' });

    my $error_uri = $self->error_url;
    if (!$error_uri->scheme) {
        $error_uri = $self->url . $self->error_url;
    }

    return $x->xml( $x->EntityDescriptor(
        $md,
        {
            entityID => $self->issuer,
            ID       => $self->_id,
        },
        $x->SPSSODescriptor(
            $md,
            {
                AuthnRequestsSigned        => $self->authnreq_signed ? 'true' : 'false',
                WantAssertionsSigned       => $self->want_assertions_signed ? 'true' : 'false',
                errorURL                   => $error_uri,
                protocolSupportEnumeration => URN_PROTOCOL,
            },

            $self->has_encryption_key
                ? ($self->_generate_key_descriptors($x, 'encryption'),
                   $self->_generate_key_descriptors($x, 'signing'))
                : $self->_generate_key_descriptors($x, 'both'),


            $self->_generate_single_logout_service($x),

            $self->_generate_assertion_consumer_service($x),
            $self->has_attribute_consuming_service ? $self->attribute_consuming_service->to_xml : (),

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
    ));
}

sub _generate_key_descriptors {
    my $self = shift;
    my $x    = shift;
    my $use  = shift;

    return
           if !$self->authnreq_signed
        && !$self->want_assertions_signed
        && !$self->sign_metadata;

    my $key = $use eq 'encryption' ? $self->_encryption_key_text : $self->_cert_text;

    $use = 'signing' if $self->signing_only && $use eq 'both';

    return $x->KeyDescriptor(
        $md,
        $use ne 'both' ? { use => $use } : {},
        $x->KeyInfo(
            $ds,
            $x->X509Data($ds, $x->X509Certificate($ds, $key)),
            $x->KeyName($ds, $self->key_name($use)),
        ),
    );
}

=head2 key_name($type)

Get the key name for either the C<signing> or C<encryption> key

=cut

sub key_name {
    my $self = shift;
    my $use  = shift;
    my $key = $use eq 'encryption' ? $self->_encryption_key_text : $self->_cert_text;
    return unless $key;
    return Digest::MD5::md5_hex($key);
}

sub _generate_single_logout_service {
    my $self = shift;
    my $x    = shift;
    return map { $x->SingleLogoutService($md, $_) } @{ $self->single_logout_service };
}

sub _generate_assertion_consumer_service {
    my $self = shift;
    my $x    = shift;
    return map { $x->AssertionConsumerService($md, $_) } @{ $self->assertion_consumer_service };
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
            ns          => { md => URN_METADATA },
            id_attr     => '/md:EntityDescriptor[@ID]',
        }
    );
    my $md = $signer->sign($metadata);

    my $xp = XML::LibXML::XPathContext->new(
        XML::LibXML->load_xml(string =>$md)
    );
    $xp->registerNs('md', URN_METADATA);
    $xp->registerNs('dsig', URN_SIGNATURE);

    my $nodes = $xp->findnodes('/md:EntityDescriptor[@ID]');
    my $rootnode = $nodes->get_node(1);

    my $child = $rootnode->firstChild;
    return $md if $child->nodeName() eq 'dsig:Signature';

    $nodes = $xp->findnodes('//dsig:Signature');
    my $signode = $nodes->get_node(1);

    $signode->unbindNode;
    $rootnode->insertBefore($signode, $child);

    return '<?xml version="1.0" encoding="UTF-8"?>' . $rootnode->toString;
}

=head2 get_default_assertion_service

Return the assertion service which is the default

=cut

sub get_default_assertion_service {
    my $self = shift;
    my $default = first { $_->{isDefault} eq 1 || $_->{isDefault} eq 'true' }
        grep { defined $_->{isDefault} } @{ $self->assertion_consumer_service };
    return $default if $default;

    $default = first { ! defined $_->{isDefault} } @{ $self->assertion_consumer_service };
    return $default if $default;

    return $self->assertion_consumer_service->[0];
}

__PACKAGE__->meta->make_immutable;
