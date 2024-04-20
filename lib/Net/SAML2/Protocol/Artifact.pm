package Net::SAML2::Protocol::Artifact;
# VERSION

use Moose;
use MooseX::Types::DateTime qw/ DateTime /;
use DateTime::Format::XSD;
use Net::SAML2::XML::Util qw/ no_comments /;
use XML::LibXML::XPathContext;

with 'Net::SAML2::Role::ProtocolMessage';

# ABSTRACT: SAML2 artifact object

=head1 NAME

Net::SAML2::Protocol::Artifact - SAML2 artifact object

=head1 SYNOPSIS

  my $artifact = Net::SAML2::Protocol::Artifact->new_from_xml(
                        xml => Net::SAML2::Binding::SOAP->request(
                                    Net::SAML2::SP->artifact_request(
                                        $art_url,
                                        $artifact
                                    )->as_xml)
                );

  or

  my $request = Net::SAML2::SP->artifact_request($art_url, $artifact)->as_xml;
  my soap_response = Net::SAML2::Binding::SOAP->request($request);
  my $artifact = Net::SAML2::Protocol::Artifact->new_from_xml(soap_response);

  # get_response returns the Response or LogoutResponse
  my art_response = $artifact->get_response();

=cut

has 'issue_instant'   => (isa => DateTime,  is => 'ro', required => 1);
has '+in_response_to'  => (required => 1);
has 'issuer'          => (isa => 'Str',     is => 'ro', required => 1);
has 'status'          => (isa => 'Str',     is => 'ro', required => 1);
has 'logoutresponse_object'  => (
    isa      => 'XML::LibXML::Element',
    is       => 'ro',
    required => 0,
    init_arg => 'logout_response',
    predicate => 'has_logout_response'
);
has 'response_object' => (
    isa      => 'XML::LibXML::Element',
    is       => 'ro',
    required => 0,
    init_arg => 'response',
    predicate => 'has_response'
);

=head1 METHODS

=cut

=head2 new_from_xml( ... )

Constructor. Creates an instance of the Artifact object, parsing the
given XML to find the response and logout_response should they exist as
well as the issuer, issue_instant and in_response_to.

Arguments:

=over

=item B<xml>

XML data

=back

=cut

sub new_from_xml {
    my($class, %args) = @_;

    my $dom = no_comments($args{xml});
    my $key_file = $args{key_file};
    my $cacert = $args{cacert};

    my $xpath = XML::LibXML::XPathContext->new($dom);
    $xpath->registerNs('saml',  'urn:oasis:names:tc:SAML:2.0:assertion');
    $xpath->registerNs('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

    my $response;
    if (my $node = $xpath->findnodes('/samlp:ArtifactResponse/samlp:Response')) {
        $response = $node->get_node(1)->cloneNode( 1 );
    }
    my $logoutresponse;
    if (my $node = $xpath->findnodes('/samlp:ArtifactResponse/samlp:LogoutResponse')) {
        $logoutresponse = $node->get_node(1)->cloneNode( 1 );
    }

    my $issue_instant;
    if (my $value = $xpath->findvalue('/samlp:ArtifactResponse/@IssueInstant')) {
        $issue_instant = DateTime::Format::XSD->parse_datetime($value);
    }

    return $class->new(
        id             => $xpath->findvalue('/samlp:ArtifactResponse/@ID'),
        in_response_to => $xpath->findvalue('/samlp:ArtifactResponse/@InResponseTo'),
        issue_instant  => $issue_instant,
        issuer         => $xpath->findvalue('/samlp:ArtifactResponse/saml:Issuer'),
        status         => $xpath->findvalue('/samlp:ArtifactResponse/samlp:Status/samlp:StatusCode/@Value'),
        $response       ? (response        => $response)        : (),
        $logoutresponse ? (logout_response => $logoutresponse)  : (),
    );
}

=head2 response

Returns the response

=cut

sub response {
    my $self = shift;
    return $self->response_object->toString;
}

=head2 logout_response

Returns the logoutresponse

=cut

sub logout_response {
    my $self = shift;
    return $self->logoutresponse_object->toString;
}

=head2 get_response ( )

Returns the LogoutResponse or Response depending on which is defined

=cut

sub get_response {
    my ($self) = @_;
    return $self->logout_response if $self->has_logout_response;
    return $self->response
}

1;
