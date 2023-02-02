package Net::SAML2::Types;
use warnings;
use strict;

# VERSION

# ABSTRACT: Custom Moose types for Net::SAML2

use Types::Serialiser;
use MooseX::Types -declare => [
    qw(
        XsdID
        SAMLRequestType
        signingAlgorithm
    )
];

use MooseX::Types::Moose qw(Str Int Num Bool ArrayRef HashRef Item);

=head2 XsdID

The type xsd:ID is used for an attribute that uniquely identifies an element in an XML document. An xsd:ID value must be an NCName. This means that it must start with a letter or underscore, and can only contain letters, digits, underscores, hyphens, and periods.

=cut

subtype XsdID, as Str,
    where {
        return 0 unless $_ =~ /^[a-zA-Z_]/;
        return 0 if $_ =~ /[^a-zA-Z0-9_\.\-]/;
        return 1;
    },
    message { "'$_' is not a valid xsd:ID" };

=head2 SAMLRequestType

Enum which consists of two options: SAMLRequest and SAMLResponse

=cut

subtype SAMLRequestType, as enum(
    [
        qw(SAMLRequest SAMLResponse)
    ]
    ),
    message { "'$_' is not a SAML Request type" };


=head2 signingAlgorithm

Enum which consists of the following options: sha244, sha256, sha384, sha512
and sha1

=cut

subtype signingAlgorithm, as enum(
    [
        qw(sha244 sha256 sha384 sha512 sha1)
    ]
    ),
    message { "'$_' is not a supported signingAlgorithm" };

1;

__END__

