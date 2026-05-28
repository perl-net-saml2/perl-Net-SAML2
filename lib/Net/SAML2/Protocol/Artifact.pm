package Net::SAML2::Protocol::Artifact;
use Moose;

extends 'Net::SAML2::Protocol';

# VERSION

use Carp                    qw/croak/;
use MooseX::Types::DateTime qw/DateTime/;
use Net::SAML2::Util        qw/xml_without_comments new_xpc/;

# ABSTRACT: SAML2 artifact object

=head1 SYNOPSIS

  my $request  = Net::SAML2::SP->artifact_request($art_url, $artifact);
  my $request  = Net::SAML2::Protocol::ArtifactResolve->new(...);
  my $response = Net::SAML2::Binding::SOAP->request($request->as_xml);
  my $artifact = Net::SAML2::Protocol::Artifact->new_from_xml($response);

  # get_response returns the LogoutResponse or Response
  my art_response = $artifact->get_response();

=head1 DESCRIPTION

=cut

has logoutresponse_object => (isa => 'XML::LibXML::Element', is => 'ro', init_arg => 'logout_response');
has response_object       => (isa => 'XML::LibXML::Element', is => 'ro', init_arg => 'response');

=head1 METHODS

=head2 my $response = $class->new(%options)

Create a response.  Probably you need C<new_from_xml()>.

As C<%options>, you can use everything provided by
the base class L<Net::SAML2::Protocol> constructor C<new()> with the
restriction that C<issue_instant>, C<status> and C<in_response_to>
are required parameters.

=cut

has '+issue_instant'  => (required => 1);
has '+status'         => (required => 1);
has '+in_response_to' => (required => 1);

=head2 my $response = $class->new_from_xml(xml => $string, %options)

Create this response object from an XML source, which is a SOAP message.
At the moment, there are no C<%options>.

=cut

sub new_from_xml {
    my ($class, %args) = @_;
    my $xpc   = new_xpc xml_without_comments $args{xml};

    my $reply = $xpc->findnodes('/samlp:ArtifactResponse')->shift
        or croak "No response received";

    my $response;
    if(my $node = $xpc->findnodes('samlp:Response', $reply)->shift) {
        $response = $node->cloneNode(1);
    }
    my $logoutresponse;
    if(my $node = $xpc->findnodes('samlp:LogoutResponse', $reply)->shift) {
        $logoutresponse = $node->cloneNode(1);
    }

    my $issue_instant;  #XXX required
    if (my $value = $xpc->findvalue('@IssueInstant', $reply)) {
        $issue_instant = DateTime::Format::XSD->parse_datetime($value);
    }

    return $class->new(
        id              => $xpc->findvalue('@ID', $reply),
        in_response_to  => $xpc->findvalue('@InResponseTo', $reply),
        issue_instant   => $issue_instant,
        issuer          => $xpc->findvalue('saml:Issuer', $reply),
        status          => $xpc->findvalue('samlp:Status/samlp:StatusCode/@Value', $reply),
        ($response       ? (response        => $response)       : ()),
        ($logoutresponse ? (logout_response => $logoutresponse) : ()),
    );
}

=head2 my $string = $response->response()

Returns the Response node as an XML string.

=cut

sub response {
    my $r = shift->response_object;
    return $r ? $r->toString : undef;
}

=head2 my $string = $response->logout_response()

Returns the LogoutResponse node as an XML string.

=cut

sub logout_response {
    my $lr = shift->logoutresponse_object;
    return $lr ? $lr->toString : undef;
}

=head2 my $string = $response->get_response()

Returns the XML string of the LogoutResponse node when defined,
otherwise the Response node.

=cut

sub get_response {
    my ($self) = @_;
    return $self->logout_response // $self->response;
}

1;
