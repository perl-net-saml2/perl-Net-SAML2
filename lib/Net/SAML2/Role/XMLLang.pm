package Net::SAML2::Role::XMLLang;
use Moose::Role;

# VERSION

# ABSTRACT: Common behaviour for XML language settings

use namespace::autoclean;

has _lang => (
    isa     => 'Str',
    is      => 'ro',
    default => 'en',
    init_arg => 'lang',
);

=head1 CONSTRUCTOR ARGUMENTS

=over

=item B<lang>

Set the language, defaults to English (C<en>).

=back

=cut

sub lang {
  my $self = shift;
  return { 'xml:lang' => $self->_lang }
}

1;
