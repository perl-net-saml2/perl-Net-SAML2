package Net::SAML2::Protocol::LogoutResponse;
use Moose;

extends 'Net::SAML2::Protocol';

# VERSION

use MooseX::Types::URI qw/Uri/;
use Net::SAML2::Util   qw/xml_without_comments new_xpc/;
use URN::OASIS::SAML2  qw/URN_ASSERTION URN_PROTOCOL/;

# ABSTRACT: SAML2 LogoutResponse Protocol object

=head1 SYNOPSIS

  my $logout_req = Net::SAML2::Protocol::LogoutResponse->new(
    issuer          => $issuer,
    destination     => $destination,
    status          => $status,
    in_response_to  => $in_response_to,
  );

=head1 DESCRIPTION

This object deals with the LogoutResponse messages from SAML.

=head1 METHODS

=head2 my $response = $class->new(%options)

Returns an instance of the LogoutResponse object.

Supported ar the C<%options> implemented by the base-class
in L<Net::SAML2::Protocol> constructor C<new()>.  In this extension,
C<status> and C<in_response_to> are required.

Additional C<%options>:

=over

=item B<substatus> => $code

The sub-status code.

=back

=cut

has '+status' => (required => 1);
has '+in_response_to' => (required => 1);
has substatus => (isa => 'Str', is => 'ro');

=head2 my $response = $class->new_from_xml(xml => $string, %options)

Create a LogoutResponse object from the given XML.

The C<%options>:

=over

=item xml => $string (required)

XML data to be processed.

=back

=cut

sub new_from_xml {
    my ($class, %args) = @_;
    my $xpc  = new_xpc xml_without_comments $args{xml};
    my $resp = $xpc->findnodes('/samlp:LogoutResponse')->shift;
    my $code = $xpc->findnodes('samlp:Status/samlp:StatusCode', $resp)->shift;

    return $class->new(
        id             => $xpc->findvalue('@ID', $resp),
        in_response_to => $xpc->findvalue('@InResponseTo', $resp),
        destination    => $xpc->findvalue('@Destination', $resp),
        session        => $xpc->findvalue('samlp:SessionIndex', $resp),
        issuer         => $xpc->findvalue('saml:Issuer', $resp),
        status         => $xpc->findvalue('@Value', $code),
        substatus      => $xpc->findvalue('samlp:StatusCode/@Value', $code),
    );
}

=head2 my $string = $response->as_xml()

Returns the LogoutResponse as XML string.

=cut

sub as_xml {
    my ($self) = @_;

    my $x = XML::Generator->new(':pretty');
    my $saml  = [ saml  => URN_ASSERTION ];
    my $samlp = [ samlp => URN_PROTOCOL  ];

    return $x->xml(
        $x->LogoutResponse($samlp, {
               ID           => $self->id,
               Version      => '2.0',
               IssueInstant => $self->issue_instant,
               Destination  => $self->destination,
               InResponseTo => $self->in_response_to },
            $x->Issuer($saml, $self->issuer),
            $x->Status($samlp, $x->StatusCode($samlp, { Value => $self->status })),
        )
    );
}

__PACKAGE__->meta->make_immutable;
