package Net::SAML2::Binding::POST;
use Moose;

extends 'Net::SAML2::Binding';

# VERSION

use Carp                 qw/croak/;
use MIME::Base64         qw/decode_base64 encode_base64/;
use Net::SAML2::XML::Sig ();

# ABSTRACT: HTTP POST binding for SAML

=head1 SYNOPSIS

  my $post = Net::SAML2::Binding::POST->new(
    cacert => '/path/to/ca-cert.pem',
  );
  my $xml = $post->handle_response($saml_response);

=head1 METHODS

=head2 my $post = $class->new(%options)

Returns an instance of the POST binding.

Supported C<%options> extend the options provided by L<Net::SAML2::Binding>
constructor C<new()>:

=over

=item B<cacert> => $filename

Path to the CA certificate for verification.

=item B<cert> => $filename

Path to a certificate that is added to the signed XML.  It needs to be the
certificate that includes the public key related to the B<key>.

=item B<cert_text> => $string

Text form of the certificate in FORMAT_ASN1 or FORMAT_PEM that is used to
verify the signed XML.

=item B<key> => $filename

Path to a key used to sign the XML.

=back

=cut

has cacert    => (isa => 'Maybe[Str]', is => 'ro');
has cert      => (isa => 'Str', is => 'ro');
has cert_text => (isa => 'Str', is => 'ro');
has key       => (isa => 'Str', is => 'ro');

=head2 my $xml = $post->handle_response($response)

Decodes and verifies the Base64-encoded SAMLResponse CGI parameter.
Returns the decoded response as XML.

=cut

sub handle_response {
    my ($self, $response) = @_;
    my $xml = decode_base64 $response;

    $self->verify_xml(
        $xml,
        no_xml_declaration => 1,
        $self->cert_text ? (cert_text => $self->cert_text) : (),
        $self->cacert    ? (cacert    => $self->cacert) : (),
    );

    return $xml;
}

=head2 my $b64_xml = $post->sign_xml($request)

Sign and encode the SAMLRequest.

=cut

sub sign_xml {
    my ($self, $request) = @_;

    defined $self->cert or croak "Need to have a cert specified";
    defined $self->key  or croak "Need to have a key specified";

    my $signer = Net::SAML2::XML::Sig->new(
        key  => $self->key,
        cert => $self->cert,
        no_xml_declaration => 1,
    );

    my $signed_message = $signer->sign_message($request);

    return encode_base64 $signed_message, "\n";
}

__PACKAGE__->meta->make_immutable;
