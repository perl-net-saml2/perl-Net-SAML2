package Net::SAML2::Binding::Redirect;
use Moose;

extends 'Net::SAML2::Binding';

# VERSION

# ABSTRACT: Redirect binding for SAML

use Net::SAML2::Types  qw/signingAlgorithm SAMLRequestType/;
use Net::SAML2::Util   qw/hash2urn urn2hash/;

use Carp               qw/croak/;
use URI                ();
use URI::QueryParam    ();
use Crypt::PK::RSA     ();
use Crypt::OpenSSL::X509 ();
use MooseX::Types::URI qw/Uri/;
use File::Slurper      qw/read_text/;
use MIME::Base64       qw/encode_base64 decode_base64/;
use URI::Escape        qw/uri_unescape/;
use IO::Compress::RawDeflate   qw/rawdeflate/;
use IO::Uncompress::RawInflate qw/rawinflate/;

=head1 SYNOPSIS

  my $redirect = Net::SAML2::Binding::Redirect->new(
    key      => '/path/to/SPsign-nopw-key.pem',  # Service Provider (SP) private key
    url      => $sso_url,                        # Service Provider Single Sign Out URL
    param    => 'SAMLRequest', # or SAMLResponse # Type of request
    cert     => $idp->cert('signing')            # Identity Provider (IdP) certificate
    sig_hash => 'sha256', # or sha224,sha384,sha512,sha1  # Signature to sign request
  );

  my $url = $redirect->sign($authnreq);
  my $ret = $redirect->verify($url);

=head1 DESCRIPTION

=head1 METHODS

=head2 my $redirect = $class->new(%options)

Creates an instance of the Redirect binding.

The following C<%options> extend the list defined by the base-class
L<Net::SAML2::Binding> constructor C<new()>:

=over

=item B<key> => $filename (pem file)

The SP's (Service Provider) also known as your application's signing key
that your application uses to sign the AuthnRequest.  Some IdPs may not
verify the signature.  Usually required when B<param> is C<SAMLRequest>.

If you don't want to sign the request, you can pass C<< insecure => 1 >>
and not provide a key; in this case, C<sign> will return a non-signed URL.

=item B<cert> => $filename

IdP's (Identity Provider's) certificate that is used to verify a signed
Redirect from the IdP.  It is used to verify the signature of the Redirect
response.  Required with B<param> being C<SAMLResponse>.

=item B<url> => $urn

IdP's SSO (Single Sign Out) service url for the Redirect binding
Required with B<param> being C<SAMLRequest>.

=item B<param> => $dir (default C<SAMLRequest>)

Query direction param name to use ('SAMLRequest' or 'SAMLResponse')

=item B<sig_hash> => $algo (default C<sha256>)

RSA signature hash algorithm used to sign request.

Supported: sha256, sha224, sha384, sha512 and sha1.

=item B<debug> => $boolean (default false)

Output extra debugging information.

=back

=cut

has cert      => (isa => 'ArrayRef[Str]', is => 'ro');
has url       => (isa =>  Uri,   is => 'ro', coerce => 1);
has key       => (isa => 'Str',  is => 'ro');
has insecure  => (isa => 'Bool', is => 'ro', default => 0 );
has debug     => (isa => 'Bool', is => 'ro');
has param     => (isa => SAMLRequestType,  is => 'ro', default => 'SAMLRequest');
has sig_hash  => (isa => signingAlgorithm, is => 'ro', default => 'sha256');

sub BUILD {
    my $self  = shift;
    my $param = $self->param;

    if($param eq 'SAMLRequest') {
        defined $self->url or croak "Need to have an URL specified";
        defined $self->key || $self->insecure or croak "Need to have a key specified";
    }
    elsif($param eq 'SAMLResponse') {
        my $certs = $self->cert || [];
        @{$self->cert} or croak "Need to have a cert specified";
    }

    return;
}

around BUILDARGS => sub {
    my ($orig, $self, %params) = @_;

    if(my $cert = $params{cert}) {
        $params{cert} = [ $cert ] if ref $cert ne 'ARRAY';
    }

    return $self->$orig(%params);
};

=head2 my $url = $redirect->get_redirect_uri($authn_request, $relaystate)

Get the redirect URI for a given request, and returns the URL to which the
user's browser should be redirected.

Accepts an optional RelayState parameter, a string which will be
returned to the requestor when the user returns from the
authentication process with the IdP.

The request is signed unless the the object has been instantiated with
C<<insecure => 1>>.

=cut

sub get_redirect_uri {
    my ($self, $request, $relaystate) = @_;
    defined $request
        or croak "Unable to create redirect URI without a request";

    my $input  = "$request";
    my $output = '';
    rawdeflate \$input => \$output;

    my $req = encode_base64 $output, '';
    my $uri = URI->new($self->url);
    $uri->query_param($self->param, $req);
    $uri->query_param(RelayState => $relaystate) if defined $relaystate;

    return $self->insecure ? $uri->as_string : $self->_sign_redirect_uri($uri);
}

sub _sign_redirect_uri {
    my ($self, $uri) = @_;

    my $key_string = read_text($self->key);
    my $pk         = Crypt::PK::RSA->new;
    my $rsa_priv   = $pk->import_key(\$key_string);

    my $hashing    = uc $self->sig_hash;
    $uri->query_param(SigAlg => hash2urn $hashing);

    my $to_sign    = $uri->query;
    my $sig        = $rsa_priv->sign_message($to_sign, $hashing, 'v1.5');

    $uri->query_param(Signature => encode_base64 $sig, '');
    return $uri->as_string;
}

=head2 my $xml = $redirect->sign($request, $relaystate)

Signs the given request, and returns the URL to which the user's
browser should be redirected.

Accepts an optional RelayState parameter, a string which will be
returned to the requestor when the user returns from the
authentication process with the IdP.

Returns the signed (or unsigned when used insure) URL for the SAML2
redirect.

=cut

sub sign {
    my ($self, $request, $relaystate) = @_;

    ! $self->insecure
        or croak "Cannot sign an insecure request!";

    return $self->get_redirect_uri($request, $relaystate);
}

=head2 my @pair = $redirect->verify($query_string)

Decode a Redirect binding URL.
Verifies the signature on the response.

  my ($request, $relaystate) = $self->verify($query_string);

Requires the *raw* query string to be passed, because L<URI> parses and
re-encodes URI-escapes in uppercase (C<%3f> becomes C<%3F>, for instance),
which leads to signature verification failures if the other party uses lower
case (or mixed case).

Returns a LIST containing the verified request and relaystate (if it exists).
Croaks on errors.

=cut

sub verify {
    my ($self, $query_string) = @_;
    $query_string =~ s#^.*?\?##;

    my %params = map { split /\=/, $_, 2 } split /\&/, $query_string;
    my $sigalg = uri_unescape $params{SigAlg};
    my $sig    = decode_base64 uri_unescape $params{Signature};

    my @signed_parts;
    foreach my $p ($self->param, qw(RelayState SigAlg)) {
        push @signed_parts, "$p=$params{$p}" if exists $params{$p};
    }

    my $signed = join '&', @signed_parts;
    $self->_verify($sigalg, $signed, $sig);

    # unpack the SAML request
    my $deflated = decode_base64 uri_unescape $params{$self->param};
    my $request  = '';
    rawinflate \$deflated => \$request;

    my $state = defined $params{RelayState} ? uri_unescape $params{RelayState} : undef;
    return ($request, $state);
}

sub _verify {
    my ($self, $sigalg, $signed, $sig) = @_;

    my $hash_name = urn2hash $sigalg;
    $hash_name || !$self->debug
        or warn "Unsupported Signature Algorithm: $sigalg, defaulting to sha256";

    $hash_name //= 'SHA256';
    foreach my $crt (@{$self->cert}) {
        my $cert    = Crypt::OpenSSL::X509->new_from_string($crt);
        my $rsa_pub = Crypt::PK::RSA->new->import_key(\$cert->pubkey);

        return 1
            if $rsa_pub->verify_message($sig, $signed, $hash_name, 'v1.5');

        warn "Unable to verify with " . $cert->subject if $self->debug;
    }

    croak "Unable to verify the XML signature";
}

__PACKAGE__->meta->make_immutable;
