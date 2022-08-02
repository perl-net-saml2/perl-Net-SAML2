use strict;
use warnings;
package Net::SAML2::Util;
# VERSION

use Crypt::OpenSSL::Random qw(random_pseudo_bytes);

# ABSTRACT: Utility functions for Net::SAML2

use Exporter qw(import);

our @EXPORT_OK = qw(
    generate_id
);

sub generate_id {
    return 'NETSAML2_' . unpack 'H*', random_pseudo_bytes(32);
}


1;

__END__

=head1 DESCRIPTION

=head1 SYNOPSIS

    use Net::SAML2::Util qw(generate_id);

=head1 METHODS

=cut

=head2 sub generate_id {}

Generate a NETSAML2 Request Id
