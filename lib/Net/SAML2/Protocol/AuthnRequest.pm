package Net::SAML2::Protocol::AuthnRequest;
use Moose;
use MooseX::Types::Moose qw /Str /;
use MooseX::Types::URI qw/ Uri /;
use MooseX::Types::Common::String qw/ NonEmptySimpleStr /;
use XML::Writer;

with 'Net::SAML2::Role::ProtocolMessage';

=head1 NAME

Net::SAML2::Protocol::AuthnRequest - SAML2 AuthnRequest object

=head1 SYNOPSIS

  my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
    issueinstant => DateTime->now,
    issuer       => $self->{id},
    destination  => $destination,
  );

=head1 METHODS

=cut

=head2 new( ... )

Constructor. Creates an instance of the AuthnRequest object. 

Arguments:

=over

=item B<issuer>

SP's identity URI

=item B<issuer_namequalifier>

NameQualifier attribute for Issuer

=item B<issuer_format>

Format attribute for Issuer

=item B<destination>

IdP's identity URI

=back

=cut

has 'issuer'        => (isa => Uri, is => 'rw', required => 1, coerce => 1);
has 'issuer_namequalifier' => (isa => Str, is => 'rw', required => 0);
has 'issuer_format' => (isa => Str, is => 'rw', required => 0);
has 'destination'   => (isa => Uri, is => 'rw', required => 0, coerce => 1);
has 'nameid' => (isa => NonEmptySimpleStr, is => 'rw', required => 0);
has 'nameid_format' => (isa => NonEmptySimpleStr, is => 'rw', required => 1);
has 'assertion_url' => (isa => Uri, is => 'rw', required => 0, coerce => 1);
has 'protocol_binding' => (isa => Uri, is => 'rw', required => 0, coerce => 1);
has 'provider_name' => (isa => Str, is => 'rw', required => 0);

=head2 as_xml( )

Returns the AuthnRequest as XML.

=cut

sub as_xml {
    my ($self) = @_;
    my $saml = 'urn:oasis:names:tc:SAML:2.0:assertion';
    my $samlp = 'urn:oasis:names:tc:SAML:2.0:protocol';
    my $x = XML::Writer->new( 
        OUTPUT => 'self', 
        NAMESPACES => 1,
        PREFIX_MAP => {
            $saml => 'saml2',
            $samlp => 'saml2p'
        }
    );

   my $req_atts = {
            ID => $self->id,
            IssueInstant => $self->issue_instant,
            Version => '2.0',
        };
        
        my $issuer_attrs = {};
        
        my $protocol_bindings = {
            'HTTP-POST' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        };

        my $att_map = {
            'assertion_url' => 'AssertionConsumerServiceURL',
            'protocol_binding' => 'ProtocolBinding',
            'provider_name' => 'ProviderName',
            'destination' => 'Destination',
            'issuer_namequalifier' => 'NameQualifier',
            'issuer_format' => 'Format',
        };

        foreach my $opt ( qw(assertion_url protocol_binding provider_name destination
            issuer_namequalifier issuer_format) ) {
            if (defined (my $val = $self->$opt())) {
                if ( $opt eq 'protocol_binding' ) {
                    $req_atts->{ $att_map->{$opt} } = $protocol_bindings->{$val};
                } elsif ($opt eq 'issuer_namequalifier' || $opt eq 'issuer_format') {
                    $issuer_attrs->{ $att_map->{$opt} } = $val;
                } else {
                    $req_atts->{ $att_map->{$opt} } = $val;
                }
            }
        }

    $x->startTag([$samlp, 'AuthnRequest'], %$req_atts);
    $x->dataElement([$saml, 'Issuer'], $self->issuer, %$issuer_attrs);
    if ($self->nameid) {
        $x->startTag([$saml, 'Subject']);
        $x->dataElement([$saml, 'NameID'], undef, NameQualifier => $self->nameid);
        $x->endTag(); # Subject
    }
    $x->endTag(); #AuthnRequest
    $x->end();
}

__PACKAGE__->meta->make_immutable;
