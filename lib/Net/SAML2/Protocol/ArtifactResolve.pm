package Net::SAML2::Protocol::ArtifactResolve;
use Moose;

extends 'Net::SAML2::Protocol';

# VERSION

use MooseX::Types::URI qw/Uri/;
use URN::OASIS::SAML2  qw/:urn/;

# ABSTRACT: ArtifactResolve protocol class

=head1 SYNOPSIS

  my $resolver = Net::SAML2::Protocol::ArtifactResolve->new(
    issuer      => $sp->id, # https://you.example.com/auth/saml
    artifact    => 'yourartifact',
    destination => $idp->art_url('soap'), # https://idp.example.net/idp
  );

  my $binding = Net::SAML2::Binding::SOAP->new(...);
  $binding->request($resolver->as_xml);

=head1 METHODS

=cut

=head2 my $request = $class->new(%options)

Constructor. Returns an instance of the ArtifactResolve request for
the given issuer and artifact.

All C<%options> as listed in the L<Net::SAML2::Protocol> constructor
C<new()> are supported, where the C<destination> is required too.

Additional options:

=over

=item B<artifact> => $name (required)

Artifact to be resolved.

=item B<provider> => $name

IdP's provider name.

=back

=cut

has '+destination' => (required => 1);
has artifact    => (isa => 'Str', is => 'ro', required => 1);
has provider    => (isa => 'Str', is => 'ro');

=head2 my $string = $request->as_xml()

Returns the request as XML string.

=cut

sub as_xml {
    my $self = shift;

    my $x     = XML::Generator->new(':pretty');
    my $saml     = [ saml  => URN_ASSERTION ];
    my $samlp    = [ samlp => URN_PROTOCOL  ];
    my $provider = $self->provider;

    return $x->xml(
        $x->ArtifactResolve($samlp, {
              ID => $self->id,
              IssueInstant => $self->issue_instant,
              Destination  => $self->destination,
              defined $provider ? (ProviderName => $provider) : (),
              Version => '2.0',
            },
            $x->Issuer($saml, $self->issuer),
            $x->Artifact($samlp, $self->artifact),
        )
    );
}

__PACKAGE__->meta->make_immutable;
