package Net::SAML2::Util;
use base 'Exporter';

use strict;
use warnings;

# VERSION

use Crypt::OpenSSL::Random qw/random_pseudo_bytes/;
use URN::OASIS::SAML2      qw/URN_ASSERTION URN_METADATA URN_PROTOCOL URN_SIGNATURE URN_ENCRYPTION/;
use XML::LibXML            ();

# ABSTRACT: Utility functions for Net::SAML2

our $DEBUG = 0;
our @EXPORT_OK = qw/
    generate_id
    deprecation_warning
    xml_without_comments
    new_xpc
    xml_bool
    hash2urn
    urn2hash
/;

=head1 DESCRIPTION

Collection of utility functions.

=head1 SYNOPSIS

  use Net::SAML2::Util qw(generate_id);

=head1 METHODS

=head2 my $unique = generate_id();

Generate a NETSAML2 Request Id.
=cut

sub generate_id { return 'NETSAML2_' . unpack 'H*', random_pseudo_bytes(32) }

=head2 deprecation_warning($warning);

Show a warning that a Deprecated feature is being used

=cut

sub deprecation_warning($) { warn "Net::SAML2 deprecation warning: $_[0]\n"; return }

=head2 $dom = xml_without_comments($string);

Parse the $string into an XML dom (XML::LibXML::Element) and remove
all comments.

This is to remediate CVE-2017-11427 XML Comments can allow for
authentication bypass in SAML2 implementations

=cut

sub xml_without_comments($) {

    # Remove comments from XML to mitigate XML comment auth bypass
    my $dom = XML::LibXML->load_xml(
        string          => $_[0],   # avoid copying of large XML
        no_network      => 1,
        load_ext_dtd    => 0,
        expand_entities => 0,
    );

    foreach my $comment_node ($dom->findnodes('//comment()')) {
        $comment_node->parentNode->removeChild($comment_node);
    }

    return $dom;
}

=head2 my $xpc = new_xpc [$node]

Create a new L<XML::LibXML::XPathContext> object, to handle your
queries.  Prefix declarations are specific, so they cannot be
accidentally forgotten.  When a C<$node> is provided, it is set
as context node.

=cut

sub new_xpc(;$)
{   my ($dom) = @_;
    my $xpc = XML::LibXML::XPathContext->new;

    $xpc->registerNs('soap-env', 'http://schemas.xmlsoap.org/soap/envelope/');
    $xpc->registerNs(saml  => URN_ASSERTION);
    $xpc->registerNs(samlp => URN_PROTOCOL);
    $xpc->registerNs(ds    => URN_SIGNATURE);   # Net::SAML2 preference
    $xpc->registerNs(dsig  => URN_SIGNATURE);   # XML::Sig preference
    $xpc->registerNs(xenc  => URN_ENCRYPTION);
    $xpc->registerNs(md    => URN_METADATA);

    $xpc->setContextNode($dom) if defined $dom;
    return $xpc;
}

=head2 my $xml = xml_bool $value

Convert a Perl space boolean into an XML boolean.  As exception,
a C<$value> of 'false' will also be seen as false.

=cut

sub xml_bool($)
{   my $v = shift;
    return !$v || $v eq 'false' ? 'false' : 'true';
}

my %hash_algo = (
    SHA1   => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    SHA256 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    SHA224 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224',
    SHA384 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    SHA512 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
);

my %hash_name = reverse %hash_algo;

=head2 my $urn = hash2urn $hash

Convert a C<$hash> code (like 'SHA1' or 'sha1') into the related C<$urn>.
Returns C<undef> when the C<$hash> is not supported.

=cut

sub hash2urn($) { return $hash_algo{uc $_[0]} }

=head2 my $hash = urn2hash $urn

Convert the C<$urn> which represents a hashing algorithm into a code
(upper case, like 'SHA1').

=cut

sub urn2hash($) { return $hash_name{$_[0]} }

1;

