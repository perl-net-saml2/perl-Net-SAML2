package Net::SAML2::XML::Util;

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
    my ($self, $xml) = @_;

    # Remove comments from XML to mitigate XML comment auth bypass
    my $tidy_obj = XML::Tidy->new(xml => $xml);
    $tidy_obj->prune('//comment()');
    return $tidy_obj->toString();
}

__PACKAGE__->meta->make_immutable;
