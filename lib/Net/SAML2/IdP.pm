package Net::SAML2::IdP;
use Moose;

# VERSION

use Crypt::OpenSSL::Verify ();
use Crypt::OpenSSL::X509   ();
use HTTP::Request::Common  qw/GET/;
use LWP::UserAgent         ();
use MooseX::Types::URI     qw/Uri/;
use Try::Tiny;
use Net::SAML2::Util       qw/xml_without_comments new_xpc/;

# ABSTRACT: SAML Identity Provider object

=head1 SYNOPSIS

  my $idp = Net::SAML2::IdP->new_from_url(
    url      => $url,
    cacert   => $cacert,
    ssl_opts => {  # see LWP::Protocol::https
        SSL_ca_file     => '/your/directory/cacert.pem',
        SSL_ca_path     => '/etc/ssl/certs',
        verify_hostname => 1,
    });

  # Get the bindings from the IdP settings:

  my $sso_url = $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');

  use URN::OASIS::SAML2 qw/BINDING_REDIRECT/;
  my $sso_url = $idp->sso_url(BINDING_REDIRECT);

  my $sso_url = $idp->sso_url('redirect');  # requires Net::SAML2 >= 2.0

=head1 DESCRIPTION

The Identity Provider (IdP) is the central authenication service.
You need either the URI of the service or an XML which describes the
service to be able to connect.  Besides, you need the public certificate
of the service to verify the origin of the configuration.

=head2 Configuring SSL

Note that L<LWP::UserAgent> is used which means that environment variables
may affect the use of https see:

=over

=item * L<PERL_LWP_SSL_CA_FILE and HTTPS_CA_FILE|https://metacpan.org/pod/LWP::UserAgent#SSL_ca_file-=%3E-$path>

=item * L<PERL_LWP_SSL_CA_PATH and HTTPS_CA_DIR|https://metacpan.org/pod/LWP::UserAgent#SSL_ca_path-=%3E-$path>

=back

=head1 METHODS

=head2 my $idp = Net::SAML2::IdP->new(%options)

Hidden constructor.  Start the IdP from its remote location or XML description
file, via the other constructors.

=cut

has entityid => (isa => 'Str',          is => 'ro', required => 1);
has cacert   => (isa => 'Maybe[Str]',   is => 'ro', required => 1);
has sso_urls => (isa => 'HashRef[Str]', is => 'ro', required => 1);
has slo_urls => (isa => 'Maybe[HashRef[Str]]', is => 'ro', default => sub { +{} });
has art_urls => (isa => 'Maybe[HashRef[Str]]', is => 'ro', default => sub { +{} });
has certs    => (isa => 'HashRef[ArrayRef[Str]]', is => 'ro', required => 1);
has formats  => (isa => 'HashRef[Str]', is => 'ro', default  => sub { {} });
has debug    => (isa => 'Bool', is => 'ro', default => 0);
has default_format => (isa => 'Str', is => 'ro');

=head2 my $idp = Net::SAML2::IdP->new_from_url(%options)

Create an IdP object by retrieving the metadata at the given URL.

Dies if the metadata can't be retrieved with reason.

Options:

=over 4

=item B<url> => $url (required)

The location of your ID providing process, either as string or URI-object.

=item B<cacert> => $cacert (required)

Certificate text.

=item B<ssl_opts> => \%config|undef

When a HASH is passed, then https is used and initiated with the given
configuration.

=item B<ua> => LWP::UserAgent-object

[2.0] Pass a prepared user-agent.

=back

=cut

sub _create_ua($) {
    my $ssl_opts = shift;
    my $ua = LWP::UserAgent->new;
    if(defined $ssl_opts)
    {   require LWP::Protocol::https;
        $ua->ssl_opts(%$ssl_opts);
    }
    return $ua;
}

sub new_from_url {
    my ($class, %args) = @_;

    my $ua  = $args{ua} // _create_ua $args{ssl_opts};
    my $res = $ua->request(GET $args{url});
    $res->is_success
        or die sprintf "Error retrieving IdP metadata: %s (%s)\n", $res->message, $res->code;

    return $class->new_from_xml(xml => $res->decoded_content, cacert => $args{cacert});
}

=head2 my $idp = Net::SAML2::IdP->new_from_xml(%options)

Constructor. Create an IdP object using the provided metadata XML
document.

=over 4

=item B<xml> => $string

The XML message which described the IdP.

=item B<cacert> => $cacert (required)

Certificate text.

=back

=cut

sub new_from_xml {
    my ($class, %args) = @_;

    my $xpc = new_xpc xml_without_comments $args{xml};

    my (%sso, %slo, %art);
    my $descr = $xpc->findnodes('//md:EntityDescriptor/md:IDPSSODescriptor')->shift;

    foreach my $sso ($xpc->findnodes("md:SingleSignOnService", $descr)) {
        my $binding    = $sso->getAttribute('Binding') or next;
        $sso{$binding} = $sso->getAttribute('Location');
    }

    foreach my $slo ($xpc->findnodes('md:SingleLogoutService', $descr)) {
        my $binding    = $slo->getAttribute('Binding') or next;
        $slo{$binding} = $slo->getAttribute('Location');
    }

    foreach my $art ($xpc->findnodes('md:ArtifactResolutionService', $descr)) {
        my $binding    = $art->getAttribute('Binding') or next;
        $art{$binding} = $art->getAttribute('Location');
    }

    my ($default_format, %formats);
    foreach my $format ($xpc->findnodes('md:NameIDFormat', $descr)) {
        $format = $format->string_value =~ s/^\s+//r =~ s/\s+$//r;

        my ($short_format) = $format =~ /^urn:oasis:names:tc:SAML:(?:2\.0|1\.1):nameid-format:(.*)$/
            or next;

        $formats{$short_format} = $format;
        $default_format //= $short_format;
    }

    my %certs;
    foreach my $key ($xpc->findnodes('md:KeyDescriptor', $descr)) {
        my $pem = $class->_get_pem_from_keynode($key);
        if(my $use = $key->getAttribute('use')) {
            push @{$certs{$use}}, $pem;
        } else {
            push @{$certs{signing}}, $pem;
            push @{$certs{encryption}}, $pem;
        }
    }

    return $class->new(
        entityid => $xpc->findvalue('//md:EntityDescriptor/@entityID'),
        sso_urls => \%sso,
        slo_urls => \%slo,
        art_urls => \%art,
        certs    => \%certs,
        cacert   => $args{cacert},
        debug    => $args{debug},
        ($default_format ? (default_format => $default_format, formats => \%formats) : ()),
    );
}

sub _get_pem_from_keynode {
    my ($self, $node) = @_;
    my $xpc = new_xpc $node;
    my ($text) = $xpc->findvalue('ds:KeyInfo/ds:X509Data/ds:X509Certificate', $node);
    $text =~ s/^\s+//gm;
    $text =~ s/\s+$//gm;

    # rewrap the base64 data from the metadata; it may not
    # be wrapped at 64 characters as PEM requires
    $text =~ s/\n//g;

    my @lines;
    while(length $text > 64) {
        push @lines, (substr $text, 0, 64, '');
    }
    push @lines, $text if length $text;

    return join "\n",
        '-----BEGIN CERTIFICATE-----',
        @lines,
        '-----END CERTIFICATE-----', '';
}


# BUILDARGS ( hashref of the parameters passed to the constructor )
# Called after the object is created to validate the IdP using the cacert

around BUILDARGS => sub {
    my ($orig, $self, %params) = @_;

    if(my $cacert = $params{cacert}) {
        my $ca = Crypt::OpenSSL::Verify->new($cacert, { strict_certs => 0, });

        my %certificates;
        my @errors;
        my $using = $params{certs} || {};
        foreach my $use (keys %$using) {
            my $certs = $using->{$use};
            foreach my $pem (@$certs) {
                my $cert = Crypt::OpenSSL::X509->new_from_string($pem);
                try {
                    $ca->verify($cert);
                    push @{$certificates{$use}}, $pem;
                }
                catch { push @errors, $_ };
            }
        }

        !$params{debug} || !@errors
            or warn "Can't verify IdP cert(s): " . (join ", ", @errors);

        $params{certs} = \%certificates;
    }

    return $self->$orig(%params);
};

=head2 my $url = $idp->sso_url($binding)

Returns the url for the SSO service using the given binding.
The C<$binding> should be the full URI or [2.0] a name.

=cut

sub sso_url {
    my ($self, $binding) = @_;
    my $uri = $self->binding($binding);
    return $self->sso_urls->{$uri};
}

=head2 my $url = $idp->slo_url($binding)

Returns the url for the Single Logout Service using the given
binding.  The C<$binding> should be the full URI or [2.0] a name.

=cut

sub slo_url {
    my ($self, $binding) = @_;
    my $uri = $self->binding($binding);
    return $self->slo_urls->{$uri};
}

=head2 my $url = $idp->art_url($binding)

Returns the url for the Artifact Resolution Service using the given
binding.  The C<$binding> should be the full URI or [2.0] a name.

=cut

sub art_url {
    my ($self, $binding) = @_;
    my $uri = $self->binding($binding);
    return $self->art_urls->{$uri};
}

=head2 my $url = $idp->cert($use)

Returns the IdP's certificates for the given use (e.g. C<signing>).

IdP's are generated from the metadata it is possible for multiple certificates
to be contained in the metadata and therefore possible for them to be there to
be multiple verified certs in C<<$self->certs>>.  At this point any certs in the IdP
have been verified and are valid for the specified use.  All certs are of type
$use are returned.

=cut

sub cert {
    my ($self, $use) = @_;
    return $self->certs->{$use};
}

=head2 my $binding = $idp->binding($urn|$name)

Returns the full binding URN for the given binding name.
[2.0] This is simply calling L<Net::SAML2::Binding>
method C<urnFor()>.

=cut

sub binding {
    my ($self, $name) = @_;
    return Net::SAML2::Binding->urnFor($name);
}

=head2 my $nameid = $idp->format($short_name)

Returns the full NameID Format URI for the given short name.

If no short name is provided, returns the URI for the default format,
the one listed first by the IdP.

If no NameID formats were advertised by the IdP, this returns C<undef>.

=cut

sub format {
    my ($self, $short_name) = @_;
    my $format = $short_name // $self->default_format;
    return defined $format ? $self->formats->{$format} : undef;
}

__PACKAGE__->meta->make_immutable;
