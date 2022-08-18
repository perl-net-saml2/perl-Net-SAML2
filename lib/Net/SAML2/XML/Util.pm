use strict;
use warnings;
package Net::SAML2::XML::Util;
# VERSION

use XML::LibXML;

# use 'our' on v5.6.0
use vars qw($VERSION @EXPORT_OK %EXPORT_TAGS $DEBUG);

$DEBUG = 0;

# We are exporting functions
use base qw/Exporter/;

# Export list - to allow fine tuning of export table
@EXPORT_OK = qw( no_comments );

# ABSTRACT: Net::SAML2::XML::Util - XML Util class

=head1 NAME

Net::SAML2::XML::Util - XML Util class.

=head1 SYNOPSIS

  my $xml = no_comments($xml);

=head1 METHODS

=cut

=head2 no_comments( $xml )

Returns the XML passed as plain XML with the comments removed

This is to remediate CVE-2017-11427 XML Comments can allow for
authentication bypass in SAML2 implementations

=cut

sub no_comments {
    my $xml = shift;

    # Remove comments from XML to mitigate XML comment auth bypass
    my $dom = XML::LibXML->load_xml(
        string          => $xml,
        no_network      => 1,
        load_ext_dtd    => 0,
        expand_entities => 0
    );

    for my $comment_node ($dom->findnodes('//comment()')) {
        $comment_node->parentNode->removeChild($comment_node);
    }

    return $dom;
}

1;
