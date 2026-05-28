package Net::SAML2::AttributeConsumingService;
use Moose;

use XML::Generator    ();
use URN::OASIS::SAML2 qw/URN_METADATA NS_METADATA/;
use Net::SAML2::Util  qw/xml_bool/;

# VERSION

# ABSTRACT: An attribute consuming service object

=head1 SYNOPSIS

  use Net::SAML2::AttributeConsumingService ();

  my $service = Net::SAML2::AttributeConsumingService->new(
    service_name => 'My Service Name',
    service_description => 'My Service description',
    index        => 1,
    default      => 0,
  );
  my $fragment = $service->to_xml;

=head1 DESCRIPTION

This contains the information for the Service Provider description, about
the location where attributes can be sent to.

=head1 METHODS

=head2 my $service = $class->new(%options)

As C<%options>, you can use:

=over 4

=item B<service_name> => $name (required)

=item B<service_description> => $string

=item B<index> => $seqnr (required)

=item B<namespace> => [ $prefix => $ns ]

=item B<default> => 0|1|'true'|'false' (default false)

Whether this is the default service.

=item B<lang> => $language (default 'en')

RFC1766 $language code added to the string fields.

=back

=cut

has namespace => (isa => 'ArrayRef', is => 'ro',
    default => sub { [ &NS_METADATA => URN_METADATA] },
);

has service_name => (isa => 'Str',  is => 'ro', required => 1);
has service_description => (isa => 'Str', is => 'ro');
has index        => (isa => 'Str',  is => 'ro', required => 1);
has default      => (isa => 'Bool', is => 'ro', default => 0);
has lang         => (isa => 'Str',  is => 'ro', default => 'en');

has attributes   => (
    isa     => 'ArrayRef[Net::SAML2::RequestedAttribute]',
    is      => 'ro',
    traits  => ['Array'],
    default => sub { [] },
    handles => { add_attribute => 'push', },
);

=head2 to_xml

Create an XML fragment for this attribute object.

=cut

sub to_xml {
    my $self  = shift;
    my $attrs = $self->attributes;

    @$attrs
        or die "Unable to create attribute consuming service, we require attributes";

    my $x  = XML::Generator->new;
    my $serv  = $self->service_description;
    my $ns    = $self->namespace;
    my $lang  = +{ 'xml:lang' => $self->lang };

    return $x->AttributeConsumingService(
        $ns,
        {
            index     => $self->index,
            isDefault => xml_bool($self->default),
        },
        $x->ServiceName($ns, $lang, $self->service_name),
        $serv ? $x->ServiceDescription($ns, $lang, $serv) : (),
        (map $_->to_xml, @$attrs),
    );
}

=head2 $service->add_attributes(@attrs).

Add requested attributes.

=cut

# Provided by Moose 'handles'.

__PACKAGE__->meta->make_immutable;
