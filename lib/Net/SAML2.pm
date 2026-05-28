package Net::SAML2;
use Moose;

our $VERSION = '0.86';

require 5.012;

# ABSTRACT: SAML2 bindings and protocol implementation

# entities
use Net::SAML2::IdP;
use Net::SAML2::SP;
use Net::SAML2::RequestedAttribute;
use Net::SAML2::AttributeConsumingService;

#! You'll get into Moose problems when the Bindings:: and Protocol::
#! extensions are loaded in their base-class.

# bindings
use Net::SAML2::Binding  ();
use Net::SAML2::Binding::Redirect;
use Net::SAML2::Binding::POST;
use Net::SAML2::Binding::SOAP;

# protocol

use Net::SAML2::Protocol ();
use Net::SAML2::Protocol::AuthnRequest;
use Net::SAML2::Protocol::LogoutRequest;
use Net::SAML2::Protocol::LogoutResponse;;
use Net::SAML2::Protocol::Assertion;
use Net::SAML2::Protocol::Artifact;
use Net::SAML2::Protocol::ArtifactResolve;

1;

__END__

=head1 SYNOPSIS

  # See TUTORIAL.md for implementation documentation and
  # t/12-full-client.t for a pseudo implementation following the tutorial

  my $idp  = Net::SAML2::IdP->new(%setup);

  my $saml = Net::SAML2->new(
     id_provider => $idp,
     issuer      => $sp_id, # Service Provider (SP) Entity ID
    #issuer      => 'http://localhost:3000/metadata.xml',
     destination => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
  );

  # in new()
  my $sso_url = $idp->sso_url($destination);

  $saml->sign(
     nameid_format => $idp->format('persistent'),
     provider_name => $provider_name,   # Service Provider (SP) Human Readable Name
     issue_instant => DateTime->now,    # Defaults to Current Time
  );

  # inside new()
  my $redirect = Net::SAML2::Binding::Redirect->new(
     key   => '/path/to/SPsign-nopw-key.pem',
     url   => $sso_url,
     param => 'SAMLRequest',   # OR 'SAMLResponse'
     cert  => '/path/to/IdP-cert.pem',
  );

  # inside sign()
  my $url = $redirect->sign($authnreq);

  # inside verify()
  my $ret = $redirect->verify($url);

  # handle the POST back from the IdP, via the browser:
  my $post = Net::SAML2::Binding::POST->new;

  if(my $ret = $post->handle_response($saml_response)) {
     my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
       xml      => decode_base64($saml_response),
       key_file => 'SP-Private-Key.pem', # Required for EncryptedAssertions
       cacert   => 'IdP-cacert.pem',     # Required for EncryptedAssertions
     );
     ...
   }

=head1 DESCRIPTION

Support for the Web Browser SSO (Single Sign-On) profile of SAML2.

=head1 METHODS


=head1 DETAILS

Net::SAML2 correctly perform the SSO process against numerous SAML
Identity Providers (IdPs). It has been tested against:

=over

=item Auth0 (requires Net::SAML2 >=0.39)

=item Azure (Microsoft Office 365)

=item GSuite (Google)

=item Jump

=item Keycloak

=item MockSAML (https://mocksaml.com/)

=item Mircosoft ADFS

=item Okta

=item OneLogin

=item PingIdentity  (requires Net::SAML2 >=0.54)

=item SAMLTEST.ID (requires Net::SAML2 >=0.63)

=item Shibboleth (requires Net::SAML2 >=0.63)

=item SimpleSAMLphp

=item DigiD (requires Net::SAML2 >= 0.63)

=item eHerkenning (requires Net::SAML2 >= 0.73)

=item eIDAS (requires Net::SAML2 >= 0.73)

=back

=head1 MAJOR CAVEATS

=over

=item SP-side protocol only

=item Requires XML metadata from the IdP

=back

=head1 AUTHOR

Timothy Legge <timlegge@gmail.com>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2026 by Venda Ltd, see the CONTRIBUTORS file for others.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

