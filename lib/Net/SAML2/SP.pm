package Net::SAML2::SP;
use Moose;

# VERSION

use Carp                 qw/croak/;
use Digest::MD5          qw/md5_hex/;
use List::Util           qw/first none/;
use MooseX::Types::URI   qw/Uri/;
use MooseX::Types::Common::String qw/NonEmptySimpleStr/;
use Crypt::OpenSSL::X509 ();
use XML::Generator       ();

use Net::SAML2::Binding::POST      ();
use Net::SAML2::Binding::Redirect  ();
use Net::SAML2::Binding::SOAP      ();
use Net::SAML2::Protocol::AuthnRequest  ();
use Net::SAML2::Protocol::LogoutRequest ();
use Net::SAML2::XML::Sig ();
use Net::SAML2::Util     qw/deprecation_warning generate_id new_xpc xml_bool/;
use Net::SAML2::Types    qw/XsdID/;
use URN::OASIS::SAML2    qw/:bindings :urn/;

# ABSTRACT: SAML Service Provider object

=head1 SYNOPSIS

  my $sp = Net::SAML2::SP->new(
    issuer => 'http://localhost:3000',
    cert   => 'sign-nopw-cert.pem',
    key    => 'sign-nopw-key.pem',
    ...
  );

=head1 DESCRIPTION

The 'Service Provider' manages the the information about the application
you want to contact.

=head1 METHODS

=head2 my $sp = $class->new(%options)

Constructor. Create an Service Provider representing object.

As C<%options>:

=over

=item B<error_url> => $uri (required)

The error URI. Can be relative to the base URI or a regular URI.

=item B<issuer> => $uri (required)

[0.78] SP's identity URI.  Before, this attributed was called "id".

=item B<cert> => $filename

Path to the signing certificate.

=item B<key> => $filename (required)

Path to the private key for the signing certificate.

=item B<encryption_key> => $filename

Path to the public key that the IdP should use for encryption. This
is used when generating the metadata.

=item B<signing_only> => $bool

Indicate that the key for signing is exclusively used for signing and not
encryption and signing.

=item B<cacert> => $filename

Path to the CA certificate for verification.

=item B<lang> => $iso_lang_code

Set the language for the C<md:localizedNameType>, defaults to C<en>.

=item B<org_name> => $string (required)

SP organisation name.

=item B<org_display_name> => $string

SP organisation display name. [2.0] Defaults to C<org_name>.

=item B<org_contact> => $email (required)

SP contact email address.

=item B<org_url> => $url

SP organization url. The url will be used as in previous versions if
this is not provided.

=item B<authnreq_signed> => $bool

Specifies in the metadata whether the SP signs the AuthnRequest
Defaults to 1 (TRUE) if not specified.

=item B<want_assertions_signed> => $bool

Specifies in the metadata whether the SP wants the Assertion from the IdP
to be signed.  Defaults to 1 (TRUE) if not specified.

=item B<sign_metadata> => $bool

Sign the metadata.  Defaults to 1 (TRUE) if not specified.

=item B<single_logout_service> => ARRAY-of-HASHes

The following option replaces the previous C<slo_url_post>, C<slo_url_soap> and
C<slo_url_redirect> constructor parameters. The former options are mapped to
this new structure.

This expects an ARRAY of HASHes where you define one or more Single Logout
Services. As example:

  [
    {
       Binding  => BINDING_HTTP_POST,    # short names not yet supported
       Location => 'https://foo.example.com/your-post-endpoint',
    },
    {
       Binding  => BINDING_HTTP_ARTIFACT,
       Location => 'https://foo.example.com/your-artifact-endpoint',
    },
  ]

=item B<assertion_consumer_service> => ARRAY-of-HASHes

The following option replaces the previous C<acs_url_post> and
C<acs_url_artifact> constructor parameters. The former options are mapped to
this new structure.

This expects an ARRAY-of-HASHes, where you define one or more Assertion
Consumer Services.

  [
    {
       Binding   => BINDING_HTTP_POST,
       Location  => 'https://foo.example.com/your-post-endpoint',
       isDefault => 'false',
       index     => 1,  # optional: otherwise assigned by order
    },
    {
       Binding   => BINDING_HTTP_ARTIFACT,
       Location  => 'https://foo.example.com/your-artifact-endpoint',
       isDefault => 'true',
       index     => 2,
    },
  ]

=item B<id> => $url

[0.78] Deprecated: replaced by C<issuer>.

=back

=cut

#XXX Do not understand the description of org_url

has _id    => (isa => XsdID, is => 'ro', init_arg => 'id',
    default => sub { generate_id() });

has issuer => (isa => 'Str', is => 'ro', required => 1);
has cert   => (isa => 'Str', is => 'ro', required => 1);
has key    => (isa => 'Str', is => 'ro', required => 1);
has cacert => (isa => 'Str', is => 'rw');
has lang   => (isa => 'Str', is => 'ro', default => 'en');

has signing_only     => (isa => 'Bool',is => 'ro');
has encryption_key   => (isa => 'Str', is => 'ro');
has error_url        => (isa =>  Uri,  is => 'ro', required => 1, coerce => 1);
has org_name         => (isa => 'Str', is => 'ro', required => 1);
has org_display_name => (isa => 'Str', is => 'ro', required => 1);
has org_contact      => (isa => 'Str', is => 'ro', required => 1);
has org_url          => (isa => 'Str', is => 'ro');

has attribute_consuming_service =>
   (isa => 'Net::SAML2::AttributeConsumingService', is => 'ro');
has authnreq_signed  => (isa => 'Bool', is => 'ro', default => 1);
has sign_metadata    => (isa => 'Bool', is => 'ro', default => 1);

has want_assertions_signed     => (isa => 'Bool',     is => 'ro', default => 1);
has assertion_consumer_service => (isa => 'ArrayRef', is => 'ro', required => 1);
has single_logout_service      => (isa => 'ArrayRef', is => 'ro', required => 1);

# These are no longer in use, but are not removed by the off change that
# someone that extended us or added a role to us with these params.
has url              => (isa => Uri,   is => 'ro', required => 1, coerce => 1);
has slo_url_soap     => (isa => 'Str', is => 'ro');
has slo_url_post     => (isa => 'Str', is => 'ro');
has slo_url_redirect => (isa => 'Str', is => 'ro');
has acs_url_post     => (isa => 'Str', is => 'ro');
has acs_url_artifact => (isa => 'Str', is => 'ro');

around BUILDARGS => sub {
    my ($orig, $self, %args) = @_;

    if(!exists $args{issuer} && exists $args{id}) {
        #XXX does not match the documentation of 'id'
        deprecation_warning "id has been renamed to issuer and should be used instead";
        $args{issuer} = delete $args{id};
    }

    # [0.60] Old code will not use 'single_logout_service'; translate
    # the old way of configuring this into the new way.

    my $base_url = $args{url};

    if(!$args{single_logout_service}) {
        #warn "Deprecation warning, please upgrade your code to use ..";
        my @slo;
        if(my $slo = $args{slo_url_soap}) {
            push @slo, +{
                Binding  => BINDING_SOAP,
                Location => $base_url . $slo,
            };
        }
        if(my $slo = $args{slo_url_redirect}) {
            push @slo, +{
                Binding  => BINDING_HTTP_REDIRECT,
                Location => $base_url . $slo,
            };
        }
        if(my $slo = $args{slo_url_post}) {
            push @slo, +{
                Binding  => BINDING_HTTP_POST,
                Location => $base_url . $slo,
            };
        }
        $args{single_logout_service} = \@slo;
    }

    # [0.60] Old code will not use 'assertion_consumer_service'; translate
    # the old way of configuring this into the new way.

    my $acs = $args{assertion_consumer_service};
    if(!$acs) {
        my @acs;
        if(my $post = delete $args{acs_url_post}) {
            push @acs, +{
                Binding   => BINDING_HTTP_POST,
                Location  => $base_url . $post,
                isDefault => 'true',
            };
        }

        if(my $arti = $args{acs_url_artifact}) {
            push @acs, +{
                Binding   => BINDING_HTTP_ARTIFACT,
                Location  => $base_url . $arti,
                isDefault => 'false',
            };
        }
        $acs = $args{assertion_consumer_service} = \@acs;
    }

    # Auto-assign indexes, if none has one.

    @$acs
        or croak "You don't have any Assertion Consumer Services configured!";

    if(none { $_->{index} } @$acs) {
        my $acs_index;
        $_->{index} = ++$acs_index for @$acs;
    }

    # 'org_display_name' is required, but often not different from the name.
    $args{org_display_name} //= $args{org_name};

    $self->$orig(%args);
};

sub id {
    my $self = shift;
    deprecation_warning "id() has been renamed to issuer()";
    return $self->issuer;
}

has _encryption_key_text => (isa => 'Str', is => 'ro', init_arg => undef, lazy => 1,
    builder => '_build_encryption_key_text');

sub _build_encryption_key_text {
    my ($self) = @_;
    my $key  = $self->encryption_key or return '';
    my $cert = Crypt::OpenSSL::X509->new_from_file($key);
    return $cert->as_string =~ s/-----[^-]*-----//gmr;
}

has _cert_text => (isa => 'Str', is => 'ro', init_arg => undef, lazy => 1,
    builder => '_build_cert_text');

sub _build_cert_text {
    my ($self) = @_;
    my $c    = $self->cert or return '';
    my $cert = Crypt::OpenSSL::X509->new_from_file($c);
    return $cert->as_string =~ s/-----[^-]*-----//gmr;
}

=head2 my $request = $sp->authn_request($dest, $nameid_format, %options)

Returns an AuthnRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

The C<%options> are passed to L<Net::SAML2::Protocol::AuthnRequest>
constructor C<new()>, where the C<issuer> is added automatically.

  use URN::OASIS::SAML2  qw(NAMEID_PERSISTENT);
  my $authnreq = $sp->authn_request(
    'https://keycloak.local:8443/realms/Foswiki/protocol/saml',
    NAMEID_PERSISTENT,
    force_authn => 1,
    is_passive  => 1,
  );

=cut

sub authn_request {
    my ($self, $destination, $nameid_format, %args) = @_;

    return Net::SAML2::Protocol::AuthnRequest->new(
        issuer              => $self->issuer,
        destination         => $destination,
        nameidpolicy_format => $nameid_format // '',
        %args,
    );
}

=head2 my $req = $sp->logout_request($dest, $nameid, $format, $session, \%params)

Returns a L<Net::SAML2::LogoutRequest> object created by this SP, intended
for the given destination, which should be the identity URI of the IdP.

Also requires the nameid (+format) and session to be logged out.

%params is a HASH for parameters to L<Net::SAML2::Protocol::LogoutRequest>
constructor C<new()>.

  %params = ( # name qualifier parameters from Assertion NameId
    name_qualifier    => "https://idp.shibboleth.local/idp/shibboleth",
    sp_name_qualifier => "https://netsaml2-testapp.local",
  );

=cut

sub logout_request {
    my ($self, $destination, $nameid, $nameid_format, $session, $params) = @_;

    return Net::SAML2::Protocol::LogoutRequest->new(
        issuer        => $self->issuer,
        destination   => $destination,
        nameid        => $nameid,
        session       => $session,
        nameid_format => $nameid_format,
        (exists $params->{sp_name_qualifier} ? (affiliation_group_id => $params->{sp_name_qualifier}) : ()),
        (exists $params->{name_qualifier}    ? (name_qualifier       => $params->{name_qualifier})    : ()),
        include_name_qualifier => $params->{include_name_qualifier} // 1,
    );
}

=head2 my $resp = $sp->logout_response($dest, $status, $irt, %options)

Returns a L<Net::SAML2::LogoutResponse> object created by this SP,
intended for the given destination, which should be the identity URI of
the IdP.

Here C<$irt> means "in_response_to", which is the ID of the
corresponding LogoutRequest object.  Also the status is taken from
that request.

All C<%options> are also passed to the resolver constructor, where
C<issuer> is added automatically.

=cut

sub logout_response {
    my ($self, $destination, $status, $in_response_to, %args) = @_;

    #XXX move
    my $status_uri = Net::SAML2::Protocol::LogoutResponse->status_uri($status);

    return Net::SAML2::Protocol::LogoutResponse->new(
        issuer          => $self->issuer,
        destination     => $destination,
        status          => $status_uri,
        in_response_to  => $in_response_to,
        %args,
    );
}

=head2 my $req = $sp->artifact_request($dest, $artifact, %options)

Returns a L<Net::SAML2::ArtifactResolve> request object created by this
SP, intended for the given destination, which should be the identity
URI of the IdP.

All C<%options> are also passed to the resolver constructor, where
C<issuer> is added automatically.

=cut

sub artifact_request {
    my ($self, $destination, $artifact, %args) = @_;

    return Net::SAML2::Protocol::ArtifactResolve->new(
        issuer       => $self->issuer,
        destination  => $destination,
        artifact     => $artifact,
        %args,
    );
}

=head2 my $post = $sp->sp_post_binding($idp, $param, %options)

Returns a L<Net::SAML2::Binding::POST> object for this SP, configured
against the given IDP for Single Sign On. The optional C<$param> specifies the name of
the query parameter involved; defaults to C<SAMLRequest>.

All C<%options> are also passed to the Post constructor, where C<url>,
C<cert>, C<key>, and C<insecure> are passed automatically.
=cut

sub sp_post_binding {
    my ($self, $idp) = (shift, shift);
    $idp or croak "Unable to create a post binding without an IDP";
    my ($param, %args) = @_ % 2 ? @_ : (undef, @_);

    return Net::SAML2::Binding::POST->new(
        url   => $idp->sso_url('post'),
        cert  => $self->cert,
        $self->authnreq_signed ? (key => $self->key) : (insecure => 1),
        param => $param // 'SAMLRequest',
        %args,
    );
}

=head2 my $binding = $sp->sso_redirect_binding($idp, $param, %args)

Returns a L<Net::SAML2::Binding::Redirect> binding object for this SP,
configured against the given IDP for Single Sign On.

The optional C<$param> specifies the name of the query parameter involved;
defaults to C<SAMLRequest>.

All C<%options> are also passed to the Redirect constructor, where C<url>,
C<cert>, C<key>, and C<insecure> are passed automatically.
=cut

sub sso_redirect_binding {
    my ($self, $idp) = (shift, shift);
    $idp or croak "Unable to create a redirect binding without an IDP";
    my ($param, %args) = @_ % 2 ? @_ : (undef, @_);

    return Net::SAML2::Binding::Redirect->new(
        url   => $idp->sso_url('redirect'),
        cert  => $idp->cert('signing'),
        $self->authnreq_signed ? (key => $self->key) : (insecure => 1),
        param => $param // 'SAMLRequest',
        %args,
    );
}

=head2 my $binding = $sp->slo_redirect_binding($idp, $param, %options)

Returns a L<Net::SAML2::Binding::Redirect> binding object for this SP,
configured against the given IDP for Single Log Out. C<$param> specifies
the name of the query parameter involved - typically C<SAMLRequest>
or C<SAMLResponse>.

All C<%options> are also passed to the Redirect constructor, where C<url>,
C<cert>, and C<key> are passed automatically.
=cut

sub slo_redirect_binding {
    my ($self, $idp) = (shift, shift);
    $idp or croak "Unable to create a redirect binding without an IDP";
    my ($param, %args) = @_ % 2 ? @_ : (undef, @_);

    return Net::SAML2::Binding::Redirect->new(
        url   => $idp->sso_url('redirect'),
        cert  => $idp->cert('signing'),
        $self->authnreq_signed ? (key => $self->key) : (insecure => 1),
        param => $param // 'SAMLRequest',
        %args,
    );
}

=head2 my $soap = $sp->soap_binding($ua, $idp_url, $idp_cert, %options)

Returns a L<Net::SAML2::Binding::SOAP> binding object for this SP,
with a destination of the given URL and signing certificate.

All other C<%options> are passed to the SOAP constructor as well, where
C<key>, C<cert>, and C<cacert> are added automatically.

=cut

sub soap_binding {
    my ($self, $ua, $idp_url, $idp_cert, %args) = @_;

    return Net::SAML2::Binding::SOAP->new(
        ua       => $ua,
        key      => $self->key,
        cert     => $self->cert,
        url      => $idp_url,
        idp_cert => $idp_cert,
        cacert   => $self->cacert,
        %args,
    );
}

=head2 my $post = $sp->post_binding(%options)

Returns a L<Net::SAML2::Binding::POST> binding object for this SP.
All arguments are passed to its constructor, where C<cacert> is
passed-on automatically.

=cut

sub post_binding {
    my ($self, %args) = @_;

    return Net::SAML2::Binding::POST->new(
        cacert => $self->cacert,
        %args,
    );
}

=head2 my $meta = $sp->generate_metadata()

Generate the metadata XML document for this SP.  Method C<metadata()>
produces the signed version of this.

=cut

my $md = [ md => URN_METADATA  ];
my $ds = [ ds => URN_SIGNATURE ];

sub generate_metadata {
    my $self = shift;

    my $x = XML::Generator->new(conformance => 'loose',
         xml => { version => "1.0", encoding => 'UTF-8' });

    my $error_uri = $self->error_url;
    if (!$error_uri->scheme) {
        $error_uri = $self->url . $self->error_url;
    }

    my $acs        = $self->attribute_consuming_service;
    my @encryption = $self->encryption_key ? ('encryption', 'signing') : 'both';
    my $lang       = { 'xml:lang' => $self->lang };

    return $x->xml( $x->EntityDescriptor(
        $md, { entityID => $self->issuer, ID => $self->_id },
        $x->SPSSODescriptor(
            $md,
            {
                AuthnRequestsSigned        => xml_bool($self->authnreq_signed),
                WantAssertionsSigned       => xml_bool($self->want_assertions_signed),
                errorURL                   => $error_uri,
                protocolSupportEnumeration => URN_PROTOCOL,
            },

            (map $self->_generate_key_descriptors($x, $_), @encryption),
            $self->_generate_single_logout_service($x),
            $self->_generate_assertion_consumer_service($x),
            $acs ? $acs->to_xml : (),

        ),
        $x->Organization(
            $md,
            $x->OrganizationName($md, $lang, $self->org_name),
            $x->OrganizationDisplayName($md, $lang, $self->org_display_name),
            $x->OrganizationURL($md, $lang, $self->org_url // $self->url),
        ),
        $x->ContactPerson(
            $md, { contactType => 'other' },
            $x->Company($md, $self->org_display_name,),
            $x->EmailAddress($md, $self->org_contact,),
        )
    ));
}

sub _generate_key_descriptors {
    my ($self, $x, $use) = @_;

    $self->authnreq_signed || $self->want_assertions_signed || $self->sign_metadata
        or return;

    my $key = $use eq 'encryption' ? $self->_encryption_key_text : $self->_cert_text;
    $use    = 'signing' if $self->signing_only && $use eq 'both';

    return $x->KeyDescriptor(
        $md,
        ($use eq 'both' ? {} : { use => $use }),
        $x->KeyInfo(
            $ds,
            $x->X509Data($ds, $x->X509Certificate($ds, $key)),
            $x->KeyName($ds, $self->key_name($use)),
        ),
    );
}

=head2 my $enckey = $sp->key_name($type)

Get the MD5-HEX of the key name for either the C<signing> or C<encryption>
key.

=cut

#XXX I don't think you want this public

sub key_name {
    my ($self, $use) = @_;
    my $key = $use eq 'encryption' ? $self->_encryption_key_text : $self->_cert_text;
    return $key ? md5_hex($key) : undef;
}

sub _generate_single_logout_service {
    my ($self, $x) = @_;
    return map $x->SingleLogoutService($md, $_), @{$self->single_logout_service};
}

sub _generate_assertion_consumer_service {
    my ($self, $x) = @_;
    return map $x->AssertionConsumerService($md, $_), @{$self->assertion_consumer_service};
}


=head2 my $string = $sp->metadata()

Returns the signed metadata as XML document for this SP.  Method
C<generated_metadata()> produces the unsigned version.

=cut

sub metadata {
    my $self = shift;

    # Create the metadata itself.

    my $metadata = $self->generate_metadata;
    $self->sign_metadata
        or return $metadata->stringify;

    # Sign the metadata

    return Net::SAML2::XML::Sig->new(
        key      => $self->key,
        cert     => $self->cert,
        x509     => 1,
        ns       => { md => URN_METADATA },
        id_attr  => '/md:EntityDescriptor[@ID]',
    )->sign_metadata($metadata->stringify);
}

=head2 my $assert = $sp->get_default_assertion_service()

Return the assertion service which is the default.

=cut

sub get_default_assertion_service {
    my $self    = shift;
    my $acs     = $self->assertion_consumer_service;

    my $default = first { my $d = $_->{isDefault} // 0; $d eq 1 || $d eq 'true' } @$acs;
    $default  //= first { ! defined $_->{isDefault} } @$acs;
    return $default // $acs->[0];
}

__PACKAGE__->meta->make_immutable;
