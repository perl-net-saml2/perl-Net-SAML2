package Net::SAML2::Role::ProtocolMessage;
use Moose::Role;

# VERSION

# ABSTRACT: Common behaviour for Protocol messages

use feature qw(state);

use namespace::autoclean;

use DateTime;
use MooseX::Types::URI qw/ Uri /;
use Net::SAML2::Util qw(generate_id);
use Net::SAML2::Types qw(XsdID);
use URN::OASIS::SAML2 qw(:status);

=head1 DESCRIPTION

Provides default ID and timestamp arguments for Protocol classes.

Provides a status-URI lookup method for the statuses used by this
implementation.

=cut

has id => (
    isa     => XsdID,
    is      => 'ro',
    builder => "_build_id"
);

has issue_instant => (
    isa     => 'Str',
    is      => 'ro',
    builder => '_build_issue_instant',
);

has issuer => (
    isa      => Uri,
    is       => 'rw',
    required => 1,
    coerce   => 1,
);

has issuer_namequalifier => (
    isa       => 'Str',
    is        => 'rw',
    predicate => 'has_issuer_namequalifier',
);

has issuer_format => (
    isa => 'Str',
    is  => 'rw',
    predicate => 'has_issuer_format',
);

has destination => (
    isa       => Uri,
    is        => 'rw',
    coerce    => 1,
    predicate => 'has_destination',
);

has in_response_to => (
    isa       => XsdID,
    is        => 'ro',
    predicate => 'has_in_response_to',
);

sub _build_issue_instant {
    return DateTime->now(time_zone => 'UTC')->strftime('%FT%TZ');
}

sub _build_id {
    return generate_id();
}

=head1 CONSTRUCTOR ARGUMENTS

=over

=item B<issuer>

URI of issuer

=item B<issuer_namequalifier>

NameQualifier attribute for Issuer

=item B<issuer_format>

Format attribute for Issuer

=item B<destination>

URI of Destination

=back

=head1 METHODS

=head2 status_uri( $status )

Provides a mapping from short names for statuses to the full status URIs.

Legal short names for B<$status> are:

=over

=item C<success>

=item C<requester>

=item C<responder>

=item C<partial>

=back

=cut


sub status_uri {
    my ($self, $status) = @_;

    state $statuses = {
        success   => STATUS_SUCCESS(),
        requester => STATUS_REQUESTER(),
        responder => STATUS_RESPONDER(),
        partial   => 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
    };

    return $statuses->{$status} if exists $statuses->{$status};
    return;
}

sub success {
    my $self = shift;

    return $self->status eq STATUS_SUCCESS() if $self->can('status');
    croak(
        "You haven't implemented the status method, unable to determine success"
    );
}

1;
