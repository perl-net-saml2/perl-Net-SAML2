# After 10 years of XML::Sig existing in Net::SAML2 as
# Net::SAML2::XML::Sig the time has come to remove it and
# return to the use of XML::Sig proper.  At the time it was
# introduced XML::Sig was not being maintained but now XML::Sig
# and Net::SAML2 have a common maintainer and the need to keep it
# embedded no longer exists.  Indeed keeping the versions in sync
# has become more bother than it is worth.
use strict;
use warnings;
package Net::SAML2::XML::Sig; use base qw(XML::Sig); 1;
# VERSION

# ABSTRACT: Net::SAML2 subclass of XML::Sig
