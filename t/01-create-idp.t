use Test::Lib;
use Test::Net::SAML2;
use Net::SAML2::IdP;

my $xml = <<XML;
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor entityID="http://sso.dev.venda.com/opensso" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>
MIIDFTCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQUFADA3MQswCQYDVQQGEwJVUzEO
MAwGA1UECgwFbG9jYWwxCzAJBgNVBAsMAmN0MQswCQYDVQQDDAJDQTAeFw0xMDEw
MDYxMjM4MTRaFw0xMTEwMDYxMjM4MTRaMFcxCzAJBgNVBAYTAlVTMQ4wDAYDVQQK
DAVsb2NhbDELMAkGA1UECwwCY3QxDTALBgNVBAMMBHNhbWwxHDAaBgkqhkiG9w0B
CQEWDXNhbWxAY3QubG9jYWwwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMhu
pJZpvu1m6ys+IrWrm3pK+onwRAYCyrgQ0RyK2cHbVLFbjBqTjKnt+PiVbnZPZUTs
tkV9oijZGQvaMy9ingJursICUQzmOfYRDm4s9gFJJOHUGYnItRhp4uj3EoWWyX8I
6Mr+g3/vNgNFvD5S9L7Hk1mSw8SnPlblZAWlFUwXAgMBAAGjgY8wgYwwDAYDVR0T
AQH/BAIwADAxBglghkgBhvhCAQ0EJBYiUnVieS9PcGVuU1NMIEdlbmVyYXRlZCBD
ZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUGy/iPd7PVObrF+lK4+ZShcbStLYwCwYDVR0P
BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDANBgkqhkiG9w0B
AQUFAAOCAQEAYoYq3Rc6jC7f8DnKxDHntHxH91F5mfp8Y3j7ALcRG/mrzkMhvxU2
O2qmh4aHzZBoY1EU9VjrVgyPJPAjFQVC+OjIE46Gavh5wobzYmVGeFLOa9NhPv50
h3EOw1eCda3VwcvStWw1OhT8cpEGqgJJVAcjwcm4VBtWjodxRn3E4zBr/xxzR1HU
ISvnu1/xomsSS+aenG5toWmhoJIKFbfhQkpnBlgGD5+12Cxn2jHpgv15262ZZIJS
WPp/0bQqdAAUzkJZPpUGUN1sTXPJexYT6na7XvLd6mvO1g+WDk6aZnW/zcT3T9tL
Iavyic/p4gZtXckweq+VTn9CdZp6ZTQtVw==
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <ArtifactResolutionService index="0" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/ArtifactResolver/metaAlias/idp"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sso.dev.venda.com/opensso/IDPSloRedirect/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPSloRedirect/metaAlias/idp"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sso.dev.venda.com/opensso/IDPSloPOST/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPSloPOST/metaAlias/idp"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/IDPSloSoap/metaAlias/idp"/>
        <ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sso.dev.venda.com/opensso/IDPMniRedirect/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPMniRedirect/metaAlias/idp"/>
        <ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sso.dev.venda.com/opensso/IDPMniPOST/metaAlias/idp" ResponseLocation="http://sso.dev.venda.com/opensso/IDPMniPOST/metaAlias/idp"/>
        <ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/IDPMniSoap/metaAlias/idp"/>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sso.dev.venda.com/opensso/SSORedirect/metaAlias/idp"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sso.dev.venda.com/opensso/SSOPOST/metaAlias/idp"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/SSOSoap/metaAlias/idp"/>
        <NameIDMappingService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://sso.dev.venda.com/opensso/NIMSoap/metaAlias/idp"/>
        <AssertionIDRequestService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://localhost:43312/opensso/AIDReqSoap/IDPRole/metaAlias/idp"/>
        <AssertionIDRequestService Binding="urn:oasis:names:tc:SAML:2.0:bindings:URI" Location="http://localhost:43312/opensso/AIDReqUri/IDPRole/metaAlias/idp"/>
    </IDPSSODescriptor>
</EntityDescriptor>
XML

my $idp = Net::SAML2::IdP->new_from_xml(
    xml    => $xml,
    cacert => 't/cacert.pem'
);

isa_ok($idp, "Net::SAML2::IdP");

my $redirect_binding = $idp->binding('redirect');
my $soap_binding     = $idp->binding('soap');

is(
    $redirect_binding,
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    "Has correct binding: HTTP-Redirect"
);
is(
    $soap_binding,
    'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
    "Has correct binding: SOAP"
);

is(
    $idp->sso_url($redirect_binding),
    'http://sso.dev.venda.com/opensso/SSORedirect/metaAlias/idp',
    'Has correct sso_url'
);
is(
    $idp->slo_url($redirect_binding),
    'http://sso.dev.venda.com/opensso/IDPSloRedirect/metaAlias/idp',
    'Has correct slo_url'
);
is(
    $idp->art_url($soap_binding),
    'http://sso.dev.venda.com/opensso/ArtifactResolver/metaAlias/idp',
    'Has correct art_url'
);

foreach my $cert (@{$idp->certs}) {
    for my $use (keys %{$cert}) {
        looks_like_a_cert($cert->{$use});
    }
};

is(
    $idp->entityid,
    'http://sso.dev.venda.com/opensso',
    "Has the correct entityid"
);

is(
    $idp->format('transient'),
    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    "has correct transient format"
);
is(
    $idp->format,
    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'has correct persistent format'
);

{
    my $xml = path('t/idp-metadata2.xml')->slurp;
    my $idp = Net::SAML2::IdP->new_from_xml(
        xml    => $xml,
        cacert => 't/cacert.pem'
    );
    isa_ok($idp, "Net::SAML2::IdP");

    my $redirect_binding = $idp->binding('redirect');
    my $soap_binding     = $idp->binding('soap');

    is(
        $redirect_binding,
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        "Has correct binding: HTTP-Redirect"
    );
    is(
        $soap_binding,
        'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
        "Has correct binding: SOAP"
    );

    is(
        $idp->sso_url($redirect_binding),
        'http://sso.dev.venda.com/opensso/SSORedirect/metaAlias/idp',
        'Has correct sso_url'
    );
    is(
        $idp->slo_url($redirect_binding),
        'http://sso.dev.venda.com/opensso/IDPSloRedirect/metaAlias/idp',
        'Has correct slo_url'
    );
    is(
        $idp->art_url($soap_binding),
        'http://sso.dev.venda.com/opensso/ArtifactResolver/metaAlias/idp',
        'Has correct art_url'
    );

    foreach my $cert (@{$idp->certs}) {
        for my $use (keys %{$cert}) {
            looks_like_a_cert($cert->{$use});
        }
    };

    is(
        $idp->entityid,
        'http://sso.dev.venda.com/opensso',
        "Has the correct entityid"
    );

    is(
        $idp->format('transient'),
        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        "has correct transient format"
    );
    is(
        $idp->format,
        'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'has correct persistent format'
    );
}

done_testing;
