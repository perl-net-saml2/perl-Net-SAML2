package Net::SAML2::Binding::POST;

use strict;
use warnings;

use Moose;
use MooseX::Types::Moose qw/ Bool Str /;
use Net::SAML2::XML::Util qw/ no_comments /;

=head1 NAME

Net::SAML2::Binding::POST - HTTP POST binding for SAML2

=head1 SYNOPSIS

  my $post = Net::SAML2::Binding::POST->new(
    cacert => '/path/to/ca-cert.pem',
    certs_as_string => 0,	# 1 - if the cacert is a string
  );

  my $ret = $post->handle_response(
    $saml_response
  );

=head1 METHODS

=cut

use Net::SAML2::XML::Sig;
use MIME::Base64 qw/ decode_base64 /;
use Crypt::OpenSSL::VerifyX509;

=head2 new( )

Constructor. Returns an instance of the POST binding.

Arguments:

=over

=item B<cert_text>

=item B<cacert>

path to the CA certificate for verification

=item B<certs_as_string>

If true (1) the cert, key, cacert are strings not files

=back

=cut

has 'cert_text' => (isa => Str, is => 'ro', required => 0);
has 'cacert' => (isa => 'Maybe[Str]', is => 'ro', required => 0);
has 'certs_as_string' => (isa => Bool, is => 'ro', required => 0);

=head2 handle_response( $response )

Decodes and verifies the response provided, which should be the raw
Base64-encoded response, from the SAMLResponse CGI parameter.

=cut

sub handle_response {
    my ($self, $response) = @_;

    # unpack and check the signature
    my $xml = no_comments(decode_base64($response));
    my $xml_opts = { x509 => 1 };
    $xml_opts->{ cert_text } = $self->cert_text if ($self->cert_text);
    my $x = Net::SAML2::XML::Sig->new($xml_opts);
    my $ret = $x->verify($xml);
    die "signature check failed" unless $ret;

    if ($self->cacert) {
        my $cert = $x->signer_cert
            or die "Certificate not provided and not in SAML Response, cannot validate";

        my $ca = '';

        if (!($self->certs_as_string)) {
            $ca = Crypt::OpenSSL::VerifyX509->new($self->cacert);
        } else {
            my $cacert = Crypt::OpenSSL::X509->new_from_string($self->cacert);
            $ca = Crypt::OpenSSL::VerifyX509->new_from_x509($cacert);
        }

        if ($ca->verify($cert)) {
            return sprintf("%s (verified)", $cert->subject);
        } else {
            return 0;
        }
    }

    return 1;
}

__PACKAGE__->meta->make_immutable;
