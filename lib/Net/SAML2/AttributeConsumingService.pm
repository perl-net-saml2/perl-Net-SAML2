package Net::SAML2::AttributeConsumingService;
use Moose;
use XML::Generator;
use URN::OASIS::SAML2 qw(URN_METADATA NS_METADATA);
# VERSION

# ABSTRACT: An attribute consuming service object

has namespace => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { return [NS_METADATA() => URN_METADATA()] },
);

has service_name => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has service_description => (
    is        => 'ro',
    isa       => 'Str',
    predicate => '_has_service_description',
);

has index => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has default => (
    is      => 'ro',
    isa     => 'Bool',
    default => 0,
);

has attributes => (
    is      => 'ro',
    isa     => 'ArrayRef[Net::SAML2::RequestedAttribute]',
    traits  => ['Array'],
    default => sub { [] },
    handles => { add_attribute => 'push', },
);

has _xml_gen => (
    is       => 'ro',
    isa      => 'XML::Generator',
    default  => sub { return XML::Generator->new() },
    init_arg => undef,
);


sub to_xml {
    my $self = shift;

    die "Unable to create attribute consuming service, we require attributes"
      unless @{ $self->attributes };

    my $xml = $self->_xml_gen();

    return $xml->AttributeConsumingService(
        $self->namespace,
        {
            index     => $self->index,
            isDefault => $self->default,
        },
        $xml->ServiceName($self->namespace, undef, $self->service_name),
        $self->_has_service_description ? $xml->ServiceDescription($self->namespace, undef, $self->service_description) : (),
        map { $_->to_xml } @{ $self->attributes },
    );
}

__PACKAGE__->meta->make_immutable;

__END__

=head1 DESCRIPTION

=head1 SYNOPSIS

  use Net::SAML2::AttributeConsumingService;

  my $service = Net::SAML2::AttributeConsumingService->new(
    # required
    service_name => 'My Service Name',
    index => 1,

    #optional
    service_description => 'My Service description',

    # defaults to:
    namespace => 'md',
    default => 0,
  );
  my $fragment = $service->to_xml;

=head1 METHODS

=head2 to_xml

Create an XML fragment for this object

=head2 add_attributes

Add a way to add requested attributes
