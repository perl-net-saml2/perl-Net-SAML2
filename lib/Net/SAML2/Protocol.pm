package Net::SAML2::Protocol;
use Moose;

# VERSION

# ABSTRACT: Common behaviour for Protocol messages

use namespace::autoclean;

use DateTime           ();
use MooseX::Types::URI qw/Uri/;
use Moose::Util::TypeConstraints qw/coerce from via class_type/;
use Net::SAML2::Util   qw/generate_id deprecation_warning/;
use Net::SAML2::Types  qw/XsdID/;
use URN::OASIS::SAML2  qw/:status/;
use Carp               qw/croak confess/;

# Extensions need to be loaded in Net::SAML2 to please Moose.

=head1 SYNOPSIS

  # base object: use extensions

=head1 DESCRIPTION

Base class for all protocol messages.

=cut

has id => (isa => XsdID, is => 'ro', builder => '_build_id');
sub _build_id { return generate_id() }

# Moose is horrible
class_type 'DateTimeClass', { class => 'DateTime' };
coerce 'Str', from 'DateTimeClass', via { $_->set_time_zone('UTC'); $_->strftime('%FT%TZ') };
has issue_instant => (isa => 'Str', is => 'ro', default => sub { DateTime->now }, coerce => 1);

has issuer         => (isa => Uri, is => 'rw', required => 1, coerce => 1);
has issuer_namequalifier => (isa => 'Str', is => 'rw');
has issuer_format  => (isa => 'Str', is => 'rw');
has destination    => (isa => Uri,   is => 'rw', coerce => 1);
has in_response_to => (isa => XsdID, is => 'ro');
has status         => (isa => 'Str', is => 'ro');

=head1 METHODS

=head2 my $message = $class->new(%options)

Do not instantiate this base class.

All C<%options> have read-accessors with the same name.
Provided C<%options> to all of the extensions:

=over

=item B<id> => $id

The sequence number for this authentication session.
Be default, a crypto safe one is generated.

=item B<issue_instant> => $timestamp

The moment this request is generated, as C<$timestamp> string or
DateTime object.  By default, this is the current moment.

=item B<issuer> => $uri (required)

URI of issuer.

=item B<issuer_namequalifier>

NameQualifier attribute for Issuer.

=item B<issuer_format>

Format attribute for Issuer.

=item B<destination> => $uri

URI of Destination.

=item B<status> => $urn

The status code (a C<$urn>) for the protocol.  This is only provided for
extensions where this makes sense.

=back

=cut

# new() Provided by Moose

=head2 my $message = $class->new_from_xml(xml => $xml, %options)

Read the message from an XML string.

=cut

sub new_from_xml {
    confess "new_from_xml() is not (yet) supported for this message type.";
}

=head2 my $string = $message->as_xml()

Generate an XML string from the data stored in this message object.

=cut

sub as_xml {
    confess "as_xml() is not (yet) supported for this message type.";
}

=head2 my $uri = $message->status_uri($status)

Provides a mapping from short names for statuses to the full status URIs.

Supported short names for C<$status> are: C<success>, C<requester>,
C<responder>, and C<partial>.

=cut

my %statuses = (
    success   => STATUS_SUCCESS,
    requester => STATUS_REQUESTER,
    responder => STATUS_RESPONDER,
    partial   => STATUS_PARTIAL_LOGOUT,
);

sub status_uri {
    my ($self, $status) = @_;
    return $statuses{$status};
}

=head2 my $is_success = $message->success

Returns true when the message was handled successfully.

=cut

sub success {
    my $self = shift;
    return $self->status eq STATUS_SUCCESS;
}

=head2 my $id = $response->response_to()

[0.85] Deprecated: use B<in_response_to()>

=cut

sub response_to {
    my $self = shift;
    deprecation_warning "Please use in_response_to instead of response_to";
    return $self->in_response_to;
} 

1;
