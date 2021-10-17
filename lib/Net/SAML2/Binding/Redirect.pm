package Net::SAML2::Binding::Redirect;

use strict;
use warnings;

use Moose;
use MooseX::Types::URI qw/ Uri /;

our $VERSION = '0.40';

# ABSTRACT: Net::SAML2::Binding::Redirect - HTTP Redirect binding for SAML

=head1 NAME

Net::SAML2::Binding::Redirect

=head1 SYNOPSIS

  my $redirect = Net::SAML2::Binding::Redirect->new(
    key     => '/path/to/SPsign-nopw-key.pem',		# Service Provider (SP) private key
    url     => $sso_url,							# Service Provider Single Sign Out URL
    param   => 'SAMLRequest' OR 'SAMLResponse',		# Type of request
    cert    => $idp->cert('signing')				# Identity Provider (IdP) certificate
    sig_hash => 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'  # Signature to sign request
  );

  my $url = $redirect->sign($authnreq);

  my $ret = $redirect->verify($url);

=head1 METHODS

=cut

use MIME::Base64 qw/ encode_base64 decode_base64 /;
use IO::Compress::RawDeflate qw/ rawdeflate /;
use IO::Uncompress::RawInflate qw/ rawinflate /;
use URI;
use URI::QueryParam;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use File::Slurp qw/ read_file /;

=head2 new( ... )

Constructor. Creates an instance of the Redirect binding.

Arguments:

=over

=item B<key>

The SP's (Service Provider) also known as your application's signing key
that your application uses to sign the AuthnRequest.  Some IdPs may not
verify the signature.

=item B<cert>

IdP's (Identity Provider's) certificate that is used to verify a signed
Redirect from the IdP.  It is used to verify the signature of the Redirect
response.

=item B<url>

IdP's SSO (Single Sign Out) service url for the Redirect binding

=item B<param>

query param name to use (SAMLRequest, SAMLResponse)

=item B<sig_hash>

RSA hash to use to sign request

Supported:

sha1, sha224, sha256, sha384, sha512

sha1 is current default but will change by version 44

=back

=cut

has 'key'   => (isa => 'Str', is => 'ro', required => 1);
has 'cert'  => (isa => 'Str', is => 'ro', required => 1);
has 'url'   => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'param' => (isa => 'Str', is => 'ro', required => 1);
has 'sig_hash' => (isa => 'Str', is => 'ro', required => 0);

=head2 sign( $request, $relaystate )

Signs the given request, and returns the URL to which the user's
browser should be redirected.

Accepts an optional RelayState parameter, a string which will be
returned to the requestor when the user returns from the
authentication process with the IdP.

=cut

sub sign {
    my ($self, $request, $relaystate) = @_;

    my $input = "$request";
    my $output = '';

    rawdeflate \$input => \$output;
    my $req = encode_base64($output, '');

    my $u = URI->new($self->url);
    $u->query_param($self->param, $req);
    $u->query_param('RelayState', $relaystate) if defined $relaystate;

    my $key_string = read_file($self->key);
    my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($key_string);

    if ( exists $self->{ sig_hash } && grep { $_ eq $self->{ sig_hash } } ('sha224', 'sha256', 'sha384', 'sha512'))
    {
        if ($self->{ sig_hash } eq 'sha224') {
            $rsa_priv->use_sha224_hash;
        } elsif ($self->{ sig_hash } eq 'sha256') {
            $rsa_priv->use_sha256_hash;
        } elsif ($self->{ sig_hash } eq 'sha384') {
            $rsa_priv->use_sha384_hash;
        } elsif ($self->{ sig_hash } eq 'sha512') {
            $rsa_priv->use_sha512_hash;
        } else {
            die "Unsupported Signing Hash";
        }
        $u->query_param('SigAlg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-' . $self->{ sig_hash });
    }
    else { #$self->{ sig_hash } eq 'sha1' or something unsupported
        $rsa_priv->use_sha1_hash;
        $u->query_param('SigAlg', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
    }

    my $to_sign = $u->query;
    my $sig = encode_base64($rsa_priv->sign($to_sign), '');
    $u->query_param('Signature', $sig);

    my $url = $u->as_string;
    return $url;
}

=head2 verify( $url )

Decode a Redirect binding URL.

Verifies the signature on the response.

=cut

sub verify {
    my ($self, $url) = @_;
    my $u = URI->new($url);

    # verify the response
    my $sigalg = $u->query_param('SigAlg');

    my $cert = Crypt::OpenSSL::X509->new_from_string($self->cert);
    my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($cert->pubkey);

    if ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256') {
        $rsa_pub->use_sha256_hash;
    } elsif ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224') {
        $rsa_pub->use_sha224_hash;
    } elsif ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384') {
        $rsa_pub->use_sha384_hash;
    } elsif ($sigalg eq 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512') {
        $rsa_pub->use_sha512_hash;
    } elsif ($sigalg eq 'http://www.w3.org/2000/09/xmldsig#rsa-sha1') {
        $rsa_pub->use_sha1_hash;
    } else {
        die "Unsupported Signature Algorithim: $sigalg";
    }

    my $sig = decode_base64($u->query_param_delete('Signature'));
    my $signed = $u->query;
    die "bad sig" unless $rsa_pub->verify($signed, $sig);

    # unpack the SAML request
    my $deflated = decode_base64($u->query_param($self->param));
    my $request = '';
    rawinflate \$deflated => \$request;

    # unpack the relaystate
    my $relaystate = $u->query_param('RelayState');

    return ($request, $relaystate);
}

__PACKAGE__->meta->make_immutable;
