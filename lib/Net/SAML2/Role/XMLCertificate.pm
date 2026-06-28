package Net::SAML2::Role::XMLCertificate;
use Moose::Role;

# VERSION

# ABSTRACT: Common behaviour for Certificates in XML

=head2 B<get_pem_from_keynode>

Get the PEM from the X509Certificate.

=cut

sub get_pem_from_keynode {
    my $self = shift;
    my $node = shift;

    $node->setNamespace('http://www.w3.org/2000/09/xmldsig#', 'ds');

    my ($text)
        = $node->findvalue("ds:KeyInfo/ds:X509Data/ds:X509Certificate", $node)
        =~ /^\s*(.+?)\s*$/s;

    # rewrap the base64 data from the metadata; it may not
    # be wrapped at 64 characters as PEM requires
    $text =~ s/\n//g;

    my @lines;
    while(length $text > 64) {
        push @lines, substr $text, 0, 64, '';
    }
    push @lines, $text;

    $text = join "\n", @lines;

    return "-----BEGIN CERTIFICATE-----\n$text\n-----END CERTIFICATE-----\n";
}

1;
