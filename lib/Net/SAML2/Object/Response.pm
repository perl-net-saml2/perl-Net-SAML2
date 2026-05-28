package Net::SAML2::Object::Response;
use Moose;

extends 'Net::SAML2::Protocol';

# VERSION

use overload '""' => 'to_string';

# ABSTRACT: A response object

use Net::SAML2::Util  qw/xml_without_comments new_xpc/;
use Carp              qw/croak/;

=head1 SYNOPSIS

  use Net::SAML2::Object::Response;

  my $xml = ...;
  my $response = Net::SAML2::Object::Response->new_from_xml(xml => $xml);

  if ($response->is_success) {
      my $assertion = $response->to_assertion(
          # See Net::SAML2::Protocol::Assertion->new_from_xml for the other
          # construction options
          key_file => ...,
          key_name => ...,
      )
  } else {  # Got a response but isn't successful
      my $status    = $response->status;
      my $substatus = $response->substatus;
      warn "We got a $status back with the following sub status $substatus";
  }

=head1 DESCRIPTION

A generic response object to be able to deal with an response from the IdP. If
the status is successful you can grab an assertion and continue your flow.

=head1 METHODS

=head2 my $response = $class->new(%options)

=head2 my $response = $class->new_from_xml(xml => $xml)

Creates this response object based on the response XML.

=cut

sub new_from_xml {
    my ($class, %args) = @_;
    my $dom = xml_without_comments $args{xml};
    my $xpc = new_xpc $dom;

    my $response  = $xpc->findnodes('/samlp:Response|/samlp:ArtifactResponse')->shift
        or croak "Unable to parse response";

    my $code_path = 'samlp:Status/samlp:StatusCode';
    if ($response->nodePath eq '/samlp:ArtifactResponse') {
       $code_path = "samlp:Response/$code_path";
    }

    my $status_node = $xpc->findnodes($code_path, $response)->shift
        or croak "Unable to parse status from response";

    my $status    = $status_node->getAttribute('Value');
    my $substatus = $xpc->findvalue('samlp:StatusCode/@Value', $status_node);

    my $nodes     = $xpc->findnodes('//saml:EncryptedAssertion|//saml:Assertion', $response);

    return $class->new(
        dom       => $dom,
        status    => $status,
        substatus => $substatus,
        issuer    => $xpc->findvalue('saml:Issuer', $response),
        id        => $response->getAttribute('ID'),
        in_response_to => $response->getAttribute('InResponseTo'),
        $nodes->size ? (assertions => $nodes) : (),
    );
}

=head2 my $xml = $response->to_string()

Explicitly stringify the response to XML.  This object is also overloaded
to stringify when interpolated.

=cut

has dom  => (isa => 'XML::LibXML::Node', is => 'ro', required => 1);

sub to_string {
    my $self = shift;
    return $self->dom->toString;
}

=head2 my $status = $response->status()

=head2 my $substatus = $response->substatus()

=cut

has status     => (isa => 'Str', is => 'ro', required => 1);
has substatus  => (isa => 'Str', is => 'ro');

=head2 my $nodelist = $response->assertions()

=head2 $response->has_assertions()

Returns the number of assertions included in this response object.

=cut

has assertions => (isa => 'XML::LibXML::NodeList', is => 'ro');

sub has_assertions()
{   my $self  = shift;
    my $nodes = $self->assertions or return;
    return $nodes->size;
}

=head2 my $assert = $response->to_assertion(%options)

Create a L<Net::SAML2::Protocol::Assertion> from the response. See
L<Net::SAML2::Protocol::Assertion/new_from_xml> for the C<%options>.

=cut

sub to_assertion {
    my ($self, %args) = @_;

    $self->assertions
        or croak "There are no assertions found in the response object";

    #XXX Hum... from parsed XML into string, then parsed again.
    return Net::SAML2::Protocol::Assertion->new_from_xml(%args, xml => $self->to_string);
}

__PACKAGE__->meta->make_immutable;
