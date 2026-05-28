package Net::SAML2::Protocol::AuthnRequest;
use Moose;

extends 'Net::SAML2::Protocol';

# VERSION
use MooseX::Types::URI            qw/Uri/;
use MooseX::Types::Common::String qw/NonEmptySimpleStr/;
use URN::OASIS::SAML2     qw/:urn BINDING_HTTP_POST/;
use Net::SAML2::Util      qw/deprecation_warning xml_bool/;

use XML::Generator        ();

# ABSTRACT: SAML2 AuthnRequest object

=head1 SYNOPSIS

  my $request = Net::SAML2::Protocol::AuthnRequest->new(
    id            => NETSAML2_Crypt::OpenSSL::Random::random_pseudo_bytes(16),
    issuer        => $sp->id,        # Service Provider (SP) Entity ID
    destination   => $destination,   # Identity Provider (IdP) SSO URL
    provider_name => $provider_name, # Service Provider (SP) Human Readable Name
    issue_instant => DateTime->now,  # Defaults to Current Time
    force_authn   => $force_authn,   # Force new authentication (Default: false)
    is_passive    => $is_passive,    # IdP should not take control of UI (Default: false)
  );

  my $request_id = $request->id;     # Store and Compare to InResponseTo
  print $request->as_xml;

=head1 METHODS

=cut

=head2 my $request = $class->new(%options)

You can provide all options as supported by base class L<Net::SAML2::Protocol>
constructor C<new()>, plus many more.

Some of the additional C<%options>:

=over

=item B<nameidpolicy_format> => $string

Format attribute for NameIDPolicy.

=item B<AuthnContextClassRef> => \@refs

=item B<AuthnContextDeclRef> => \@refs

=item B<RequestedAuthnContext_Comparison> => $string

Value for the I<Comparison> attribute in case I<RequestedAuthnContext> is
included (see above). Default value is I<exact>.

=item B<identity_providers> => \@names

Then Identity providers.  If used the E<lt>ScopingE<gt> element is added
to the XML.

=back

If either C<AuthnContextClassRef> or C<AuthnContextDeclRef>
is given, then the C<RequestedAuthnContext> will be included
in the request.

=cut

has nameid           => (isa => NonEmptySimpleStr, is => 'rw');
has nameidpolicy_format => (isa => 'Str',  is => 'rw');
has nameid_allow_create => (isa => 'Bool', is => 'rw', default => 0);
has assertion_url    => (isa =>  Uri,  is => 'rw', coerce => 1);
has assertion_index  => (isa => 'Int', is => 'rw');
has attribute_index  => (isa => 'Int', is => 'rw');
has protocol_binding => (isa =>  Uri,  is => 'rw', coerce => 1);
has provider_name    => (isa => 'Str', is => 'rw');
has force_authn      => (isa => 'Bool', is => 'ro');
has is_passive       => (isa => 'Bool', is => 'ro');

has AuthnContextClassRef => (isa => 'ArrayRef[Str]', is => 'rw', default => sub { [] });
has AuthnContextDeclRef  => (isa => 'ArrayRef[Str]', is => 'rw', default => sub { [] });
has RequestedAuthnContext_Comparison => (isa => 'Str', is => 'rw', default => 'exact');
has identity_providers   => (isa => 'ArrayRef[Str]', is => 'ro', default => sub { [] });

around BUILDARGS => sub {
    my $orig = shift;
    my $self = shift;

    my %params = @_;
    if ($params{nameid_format} && !defined $params{nameidpolicy_format}) {
        deprecation_warning "You are using nameid_format, "
          . "this field has changed to nameidpolicy_format. This field will "
          . "be used for other purposes in an upcoming release. Please change "
          . "your code ASAP.";
        $params{nameidpolicy_format} = $params{nameid_format};
    }

    $self->$orig(%params);
};

=head2 my $string = $request->as_xml( )

Returns the AuthnRequest message as XML string.

=cut

my $samlp = [ samlp => URN_PROTOCOL  ];
my $saml  = [ saml  => URN_ASSERTION ];

my %protocol_bindings = (
    'HTTP-POST' => BINDING_HTTP_POST,
);

sub as_xml {
    my ($self) = @_;

    my $x   = XML::Generator->new(':std');
    my $protocol_binding = $protocol_bindings{$self->protocol_binding // ''};

    my %req_attrs = (
        ID              => $self->id,
        IssueInstant    => $self->issue_instant,
        Version         => '2.0',
        AssertionConsumerServiceURL    => $self->assertion_url,
        AssertionConsumerServiceIndex  => $self->assertion_index,
        AttributeConsumingServiceIndex => $self->attribute_index,
        ProtocolBinding => $protocol_binding,
        ProviderName    => $self->provider_name,
        Destination     => $self->destination,
        (defined $self->force_authn ? (ForceAuthn => xml_bool($self->force_authn)) : ()),
        (defined $self->is_passive  ? (IsPassive  => xml_bool($self->is_passive))  : ()),
    );

    my @are_null = grep !defined $req_attrs{$_}, keys %req_attrs;
    delete @req_attrs{@are_null} if @are_null;

    my %issuer_attrs = (
        NameQualifier   => $self->issuer_namequalifier,
        Format          => $self->issuer_format,
    );
    @are_null = grep !defined $issuer_attrs{$_}, keys %issuer_attrs;
    delete @issuer_attrs{@are_null} if @are_null;

    return $x->AuthnRequest($samlp,
        \%req_attrs,
        $x->Issuer($saml, \%issuer_attrs, $self->issuer),
        $self->_set_name_id($x),
        $self->_set_name_policy_format($x),
        $self->_set_requested_authn_context($x),
        $self->_set_scoping($x),
    );
}

sub _set_scoping {
    my ($self, $x) = @_;
    my $providers  = $self->identity_providers;
    @$providers or return undef;

    my @providers = map $x->IDPEntry($samlp, { ProviderID => $_ }), @$providers;
    return $x->Scoping($samlp, $x->IDPList($samlp, @providers));
}

sub _set_name_id {
    my ($self, $x) = @_;
    my $nameid = $self->nameid;
    defined $nameid or return undef;
    return $x->Subject($saml, $x->NameID($saml, { NameQualifier => $nameid }));
}

sub _set_name_policy_format {
    my ($self, $x) = @_;
    my $format = $self->nameidpolicy_format;
    defined $format or return undef;

    return $x->NameIDPolicy($samlp, {
        Format => $format,
        ($self->nameid_allow_create ? (AllowCreate => xml_bool($self->nameid_allow_create)) : ()),
    });
}

sub _set_requested_authn_context {
    my ($self, $x) = @_;

    my $c = $self->AuthnContextClassRef;
    my $d = $self->AuthnContextDeclRef;
    @$c || @$d or return;

    my @class = map $x->AuthnContextClassRef($saml, undef, $_), @$c;
    my @decl  = map $x->AuthnContextDeclRef($saml, undef, $_), @$d;

    return $x->RequestedAuthnContext(
        $samlp,
        { Comparison => $self->RequestedAuthnContext_Comparison },
        @class,
        @decl,
    );
}

__PACKAGE__->meta->make_immutable;
