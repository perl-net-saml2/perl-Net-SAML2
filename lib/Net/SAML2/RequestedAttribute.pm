package Net::SAML2::RequestedAttribute;
use Moose;

# VERSION

use XML::Generator;
use URN::OASIS::SAML2   qw/URN_METADATA NS_METADATA/;

# ABSTRACT: RequestedAttribute class

=head1 SYNOPSIS

  use Net::SAML2::RequestedAttribute;

  my $attr = Net::SAML2::RequestedAttribute->new(
    name => 'Some:urn',
    friendly_name => 'foo',
    required => 1,
  );

  my $fragment = $attr->to_xml();

=head1 DESCRIPTION

A requested attribute can hold other attributes than the ones specified in the
XSD of
L<https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd>.

=head1 METHODS

=head2 my $attr = $class->new(%options)

As C<%options>, you can choose from:

=over 4

=item B<name> => $urn (required)

=item B<namespace> => [ $prefix => $ns ]

=item B<required> => $bool (default false)

=item B<friendly_name> => $string

=item B<name_format> => $string

=back

=cut

has name          => (isa => 'Str', is => 'ro', required => 1);
has namespace     => (isa => 'ArrayRef', is => 'ro',
    default => sub { [ &NS_METADATA => URN_METADATA ] });

has required      => (isa => 'Bool', is => 'ro', default => 0);
has friendly_name => (isa => 'Str', is => 'ro');
has name_format   => (isa => 'Str', is => 'ro');

has _xml_gen      => (isa => 'XML::Generator', is => 'ro', init_arg => undef,
    default => sub { XML::Generator->new },
);

=head2 my $string = $attr->to_xml();

Create an XML fragment.

=cut

sub to_xml {
    my $self  = shift;
    my %attrs = $self->_build_attributes;
    my $x     = $self->_xml_gen();
    return $x->RequestedAttribute($self->namespace, \%attrs);
}

=head2 my %attrs = $attr->_build_attributes()

This method allows you to override the attributes for the
RequestedAttribute node where you can add/remove/replace or change the
order of the attributes.

=cut

# In other OO frameworks this method would have been protected or common
# (Object::Pad/Corrina).

sub _build_attributes {
    my $self     = shift;
    my $friendly = $self->friendly_name // '';

    return +(
        $self->required ? (isRequired => 'true') : (),
        Name => $self->name,
        length $friendly ? (FriendlyName => $friendly) : (),
    );
}

__PACKAGE__->meta->make_immutable;
