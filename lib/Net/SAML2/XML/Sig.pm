
package Net::SAML2::XML::Sig;
use base 'XML::Sig';

#!!! No Moose

#VERSION

#ABSTRACT: Interface to XML::SIG

use Carp              qw/croak confess/;
use Net::SAML2::Util  qw/new_xpc/;
use XML::LibXML;
use URN::OASIS::SAML2 qw(URN_SIGNATURE);


=head1 SYNOPSIS

  # Module for internal use only
  my $signer = Net::SAML2::XML::Sig->new(key => ..., cert => ...);
  my $xml    = $signer->sign_metadata($sp, $metadata);

=head1 DESCRIPTION

The implementation of L<XML::SIG> does not really produce the
results we need: we need some tweaks.  Besides, the calling
convention with values in a HASH is too different to ignore.

=head1 METHODS

=head2 my $signer = $class->new(\%options)

=head2 my $signer = $class->new(%options)

Instantiate the signer logic.

As C<%options>:
C<key> (required),
C<cert> (required),
C<sig_hash> (default sha256),
C<digest_hash> (default sha256),
C<x509>,
and everything else L<XML::Sig> constructor C<new()> likes to eat.

=cut

#XXX It would have been nice if XML::Sign separated its construction
#XXX into a 'bless' and 'init', like this:
#XXX   sub new($) { my ($class, $args) = @_; (bless {}, $class)->init($args) }
#XXX   sub init($) { my ($self, $args) = @_; ... }

sub new {
    my $class = shift;
    my $args  = @_==1 ? shift : +{@_};
    $args->{sig_hash}    //= 'sha256';
    $args->{digest_hash} //= 'sha256';

    return $class->SUPER::new($args);
}

=head2 my $signed_meta = $signer->sign_metadata($meta, %options)
=cut

sub sign_metadata {
    my ($self, $metadata) = @_;

    my $md       = $self->sign($metadata);

    #XXX Apparently, the XML::Sig puts it on the wrong place.
    # Relocate the Signature

    my $xml      = XML::LibXML->load_xml(string => $md);
    my $xpc      = new_xpc $xml;

    my $rootnode = $xpc->findnodes('/md:EntityDescriptor[@ID]')->shift;
    my $child    = $rootnode->firstChild;
    return $md if $child->nodeName eq 'dsig:Signature';

    my $signode  = $xpc->findnodes('//dsig:Signature')->shift;
    $signode->unbindNode;
    $rootnode->insertBefore($signode, $child); 

    # Create the XML
    return '<?xml version="1.0" encoding="UTF-8"?>' . $rootnode->toString;
}

=head2 my $signed_msg = $signer->sign_message($msg, %options)
=cut

sub sign_message {
    my ($self, $message, %args) = @_;
    my $signed = $self->sign($message);

    # saml-schema-protocol-2.0.xsd Schema hack
    # 
    # The real fix here is to fix XML::Sig to accept a XPATH to
    # place the signature in the correct location.  Or use XML::LibXML 
    # here to do so.
    #
    # The ds:Signature (should it exist) MUST follow the saml:Issuer
    #
    # 1: saml:Issuer
    # 2: ds:Signature
    # 3: samlp:Artifact
    #
    # Seems like an oversight in the SAML schema specification but..

    #XXX "sequence" enforces strict order so: XML::Sig is wrong.
    #XXX No XPATH needed: always after the Issuer.

    $signed =~ s!(<dsig:Signature.*?</dsig:Signature>)!!s;
    my $signature = $1;
    $signed =~ s/(<\/saml:Issuer>)/$1$signature/;

    return $signed;
}

=head2 my $success = $signer->verify($xml, %options)
=cut

sub verify {
    my ($self, $xml, %args) = @_;
    return $self->SUPER::verify($xml);  # no args yet
}

1;
