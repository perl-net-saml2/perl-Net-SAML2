package Net::SAML2::Types;

use warnings;
use strict;

# VERSION

# ABSTRACT: Custom Moose types for Net::SAML2

use Types::Serialiser;
use MooseX::Types::Moose qw/Str Int Num Bool ArrayRef HashRef Item/;
use MooseX::Types -declare => [ qw/XsdID SAMLRequestType signingAlgorithm/ ];

=head1 DESCRIPTION

The module adds a few types to the existing Moose types, to be used
in attribute declarations of objects.

=head1 ADDITIONAL TYPES

=head2 type 'XsdID'

The type C<XsdID> is used for an attribute that uniquely identifies an
element in an XML document. An C<XsdID> value must be an NCName. This
means that it must start with a letter or underscore, and can only
contain letters, digits, underscores, hyphens, and periods.

=cut

subtype XsdID, as Str,
    where { /^[a-zA-Z_][a-zA-Z0-9_\.\-]*$/ },
    message { "'$_' is not a valid xsd:ID" };

=head2 type 'SAMLRequestType'

Enum which consists of two options: the strings C<SAMLRequest>
and C<SAMLResponse>.

=cut

subtype SAMLRequestType, as enum( [ qw(SAMLRequest SAMLResponse) ]),
    message { "'$_' is not a SAML Request type" };

=head2 type 'signingAlgorithm'

Enum which consists of the following signing algorithm names (as string):
C<sha244>, C<sha256>, C<sha384>, C<sha512>, and C<sha1>.

=cut

subtype signingAlgorithm, as enum([ qw(sha244 sha256 sha384 sha512 sha1) ]),
    message { "'$_' is not a supported signingAlgorithm" };

1;
