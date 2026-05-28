package Net::SAML2::Binding;
use Moose;

# VERSION

use Net::SAML2::XML::Sig   ();
use Crypt::OpenSSL::Verify ();
use Crypt::OpenSSL::X509   ();

use Carp                   qw(croak);
use List::Util             qw(any);
use Try::Tiny;
use URN::OASIS::SAML2      qw/:binding/;

# Extensions need to be loaded in Net/SAML2.pm to please Moose.

# ABSTRACT: base class for bindings

=head1 SYNOPSIS

  # base-class for bindings: do not instantiate.

=head1 DESCRIPTION

=head1 METHODS

=head2 my $binding = $class->new(%options)

=over 4

=item B<cacert> => $filename

Used for a trust model, if lacking, everything is trusted.

=item B<anchors> => \%map

Check specific certificates based on subject/issuer or issuer HASH.

=back

=cut

# new() handled by Moose

has cacert   => (isa => 'Str', is => 'ro');
has anchors  => (isa => 'HashRef', is => 'ro');

=head2 $binding->verify_xml($xml, %options)

This method will croak when the verification fails.

When you pass options C<cacert> or C<anchors>, they will overrule
this object's attributes.

Other C<%options> are passed to C<Net::SAML2::XML::Sig> constructor
C<new()>, except for C<cacert> and C<anchors>.

Example:

  $binding->verify_xml($xml,
      no_xml_declaration => 1,  # xml production

      anchors => {   # one of the following is allowed
          subject     => ["subject a",     "subject b"],
          issuer      => ["Issuer A",      "Issuer B"],
          issuer_hash => ["Issuer A hash", "Issuer B hash"],
      },
  );

=cut

sub verify_xml {
    my ($self, $xml, %args) = @_;
    my $cacert   = delete $args{cacert}  || $self->cacert;
    my $anchors  = delete $args{anchors} || $self->anchors;

    my $signer = Net::SAML2::XML::Sig->new(%args);
    $signer->verify($xml) or croak "XML signature check failed";

    $anchors || $cacert or return;

    my $cert = $signer->signer_cert
        or die "Certificate not provided in SAML Response, cannot validate.\n";

    if($cacert) {
        my $ca = Crypt::OpenSSL::Verify->new($cacert, { strict_certs => 0 });
        try { $ca->verify($cert) }
        catch {
            croak "Could not verify CA certificate: $_";
        };
    }

    if($anchors) {
        ref $anchors eq 'HASH'
            or croak "Unable to verify anchor trust";

        my ($key) = keys %$anchors;
        any { $key eq $_ } qw(subject issuer issuer_hash)
            or croak "Unable to verify anchor trust, requires subject, issuer or issuer_hash";

        my $got  = $cert->$key;
        my $want = $anchors->{$key};
        $want    = [ $want ] if ref $want ne 'ARRAY';

        any { $_ eq $got } @$want
            or croak "Could not verify trust anchors of certificate!";
    }

    return undef;
}

=head2 my $urn = $class->urnFor($urn|$name)

[2.0] Returns the full binding URN for the given binding short C<$name>.
Supports C<post>, C<redirect>, C<soap>, and C<artifact>, and C<poas>.
When you pass anything else (for instance an C<$urn>), it is simply
returned.

=cut

my %bindings = (
   post     => BINDING_HTTP_POST,
   artifact => BINDING_HTTP_ARTIFACT,
   redirect => BINDING_HTTP_REDIRECT,
   soap     => BINDING_SOAP,
   poas     => BINDING_POAS,
);

sub urnFor {
    my ($self, $name) = @_;
    return $bindings{$name} // $name;
}

1;
