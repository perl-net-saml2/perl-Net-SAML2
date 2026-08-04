use strict;
use warnings;
use Test::Lib;
use Test::Net::SAML2;
use File::Temp qw(tempdir);
use POSIX qw(strftime);

use Net::SAML2::Protocol::Assertion;
use Net::SAML2::Object::Response;
use XML::Sig;

# cert_text pins one exact certificate; cacert verifies a CA chain instead.
# Real IdPs often publish a CA-issued (not self-signed) signing cert, which
# cacert-chain verification can't trust unless the caller also trusts that
# CA -- not how SAML metadata trust works. Per OASIS "SAML V2.0 Metadata
# Interoperability Profile Version 1.0" (24 Oct 2019), section 2.6.1 "Key
# Processing", a consumer "MUST NOT apply additional criteria of any kind
# on the acceptance, or validity, of the keys found within" metadata: trust
# is keyed on the published certificate itself, no CA chain involved.
#
# This file builds that shape (a small CA + a leaf cert it issues) and
# verifies cert_text as the trust anchor instead, in both
# Protocol::Assertion and Object::Response -- the latter previously
# accepted cert_text but silently dropped it without ever using it
my $dir = tempdir(CLEANUP => 1);

my $ca_key = "$dir/ca.key";
my $ca_crt = "$dir/ca.crt";
system("openssl genrsa -out $ca_key 2048 2>/dev/null") == 0 or die "ca keygen";
system("openssl req -new -x509 -key $ca_key -out $ca_crt -days 1 "
     . "-subj '/CN=Test Intermediate CA' 2>/dev/null") == 0 or die "ca certgen";

my $idp_key = "$dir/idp.key";
my $idp_csr = "$dir/idp.csr";
my $idp_crt = "$dir/idp.crt";
system("openssl genrsa -out $idp_key 2048 2>/dev/null") == 0 or die "idp keygen";
system("openssl req -new -key $idp_key -out $idp_csr "
     . "-subj '/CN=Test IdP (CA-issued)' 2>/dev/null") == 0 or die "idp csr";
system("openssl x509 -req -in $idp_csr -CA $ca_crt -CAkey $ca_key -CAcreateserial "
     . "-out $idp_crt -days 1 2>/dev/null") == 0 or die "idp certgen (CA-issued)";

sub make_assertion {
    my %p = @_;
    my $id     = $p{id}     // "_legit_" . int(rand(1e9));
    my $nameid = $p{nameid} // 'lowuser@victim.com';
    my $issuer = $p{issuer} // 'http://idp.test/idp';
    my $now    = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(time - 60));
    my $exp    = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(time + 3600));
    my $aud    = $p{audience} // 'http://sp.test';
    my $recip  = $p{recipient} // 'http://sp.test/saml/post';

    return <<"XML";
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="$id" Version="2.0" IssueInstant="$now">
  <saml:Issuer>$issuer</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">$nameid</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData InResponseTo="_req_$$" NotOnOrAfter="$exp" Recipient="$recip"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="$now" NotOnOrAfter="$exp">
    <saml:AudienceRestriction>
      <saml:Audience>$aud</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="$now" SessionIndex="_sess_$$">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
XML
}

sub wrap_in_response {
    my %p = @_;
    my $inner = $p{inner};
    my $resp_id = "_resp_$$" . "_" . int(rand(1e9));
    my $now = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime());
    my $dest = $p{destination} // 'http://sp.test/saml/post';
    # Net::SAML2::Role::ProtocolMessage's in_response_to is `isa => XsdID`
    # (not Maybe[XsdID]), and Object::Response::new_from_xml unconditionally
    # passes it through from the Response's InResponseTo attribute -- so it
    # must always be present and a valid xsd:ID, even though these fixtures
    # don't model a real preceding AuthnRequest.
    my $in_response_to = "_authnreq_" . int(rand(1e9));
    return <<"XML";
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="$resp_id" Version="2.0" IssueInstant="$now"
                InResponseTo="$in_response_to"
                Destination="$dest">
  <saml:Issuer>http://idp.test/idp</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
$inner
</samlp:Response>
XML
}

my $signer = XML::Sig->new({
    x509               => 1,
    key                => $idp_key,
    cert               => $idp_crt,
    no_xml_declaration => 1,
});

# See t/32-xsw-defenses.t for why the Signature needs repositioning.
sub sign_schema_compliant {
    my ($s, $xml) = @_;
    my $signed = $s->sign($xml);
    my ($sig) = $signed =~ m{(<(?:ds|dsig):Signature\b.*?</(?:ds|dsig):Signature>)}s;
    return $signed unless $sig;
    $signed =~ s{\Q$sig\E}{}s;
    $signed =~ s{(</saml:Issuer>)}{$1$sig}s;
    return $signed;
}

my $idp_crt_pem = do {
    open my $fh, '<', $idp_crt or die $!;
    local $/;
    <$fh>;
};

# ============================================================
# Sanity:
# cacert-chain verification should fail for a CA-issued (not self-signed) cert
# used as its own "CA file".
# This is the exact production setup for DigiD/Logius: the metadata only
# contains a "leaf" certificate signed by QuoVadis that is used for signing,
# not any of the intermediates or root CA certificate.
# ============================================================
{
    my $assertion_xml = make_assertion(nameid => 'lowuser@victim.com');
    my $signed = sign_schema_compliant($signer, $assertion_xml);
    my $response = wrap_in_response(inner => $signed);

    throws_ok(
        sub {
            Net::SAML2::Protocol::Assertion->new_from_xml(
                xml    => $response,
                cacert => $idp_crt,
            );
        },
        qr/chains to the configured cacert/,
        'sanity: cacert-chain verification fails for a CA-issued (non-self-signed) cert'
    );
}

# ============================================================
# Test 1: cert_text pins the same CA-issued cert directly and succeeds
# ============================================================
{
    my $assertion_xml = make_assertion(nameid => 'lowuser@victim.com');
    my $signed = sign_schema_compliant($signer, $assertion_xml);
    my $response = wrap_in_response(inner => $signed);

    my $a = eval {
        Net::SAML2::Protocol::Assertion->new_from_xml(
            xml       => $response,
            cert_text => $idp_crt_pem,
        );
    };
    ok($a, 'cert_text pins a CA-issued cert successfully') or diag $@;
    is($a && $a->nameid, 'lowuser@victim.com', 'correct nameid extracted via cert_text pinning');
}

# ============================================================
# Test 2: a non-matching cert_text is rejected, not silently trusted
# ============================================================
{
    my ($wrong_key, $wrong_csr, $wrong_crt) = ("$dir/wrong.key", "$dir/wrong.csr", "$dir/wrong.crt");
    system("openssl genrsa -out $wrong_key 2048 2>/dev/null") == 0 or die "wrong keygen";
    system("openssl req -new -key $wrong_key -out $wrong_csr "
         . "-subj '/CN=Wrong CA-issued IdP' 2>/dev/null") == 0 or die "wrong csr";
    system("openssl x509 -req -in $wrong_csr -CA $ca_crt -CAkey $ca_key -CAcreateserial "
         . "-out $wrong_crt -days 1 2>/dev/null") == 0 or die "wrong certgen";
    my $wrong_crt_pem = do {
        open my $fh, '<', $wrong_crt or die $!;
        local $/;
        <$fh>;
    };

    my $assertion_xml = make_assertion(nameid => 'lowuser@victim.com');
    my $signed = sign_schema_compliant($signer, $assertion_xml);
    my $response = wrap_in_response(inner => $signed);

    throws_ok(
        sub {
            Net::SAML2::Protocol::Assertion->new_from_xml(
                xml       => $response,
                cert_text => $wrong_crt_pem,
            );
        },
        qr/chains to the configured cacert|No trusted signature found/,
        'a cert_text that does not match the embedded cert is rejected'
    );
}

# ============================================================
# Test 3: XSW different-ID wrapping is still defended under cert_text
# pinning (mirrors t/32-xsw-defenses.t's Test 3, but with cert_text
# instead of cacert as the trust anchor)
# ============================================================
{
    my $legit_id = "_legit_" . int(rand(1e9));
    my $legit_xml = make_assertion(id => $legit_id, nameid => 'lowuser@victim.com');
    my $signed_legit = sign_schema_compliant($signer, $legit_xml);

    my $atk_id = "_attacker_" . int(rand(1e9));
    my $atk_xml = make_assertion(id => $atk_id, nameid => 'admin@victim.com');

    my $payload = "$atk_xml\n<wrapper xmlns=\"urn:wrapper\">$signed_legit</wrapper>";
    my $response = wrap_in_response(inner => $payload);

    my $a = eval {
        Net::SAML2::Protocol::Assertion->new_from_xml(
            xml       => $response,
            cert_text => $idp_crt_pem,
        );
    };
    my $err = $@;
    ok($a, 'XSW different-ID under cert_text pinning: new_from_xml returned an Assertion')
        or diag $err;
    is($a && $a->nameid, 'lowuser@victim.com',
        'XSW different-ID under cert_text pinning: extracted NameID is the LEGIT one');
}

# ============================================================
# Test 4: Object::Response actually reads and propagates cert_text
# ============================================================
{
    my $assertion_xml = make_assertion(nameid => 'lowuser@victim.com');
    my $signed = sign_schema_compliant($signer, $assertion_xml);
    my $response_xml = wrap_in_response(inner => $signed);

    my $response = eval {
        Net::SAML2::Object::Response->new_from_xml(
            xml       => $response_xml,
            cert_text => $idp_crt_pem,
        );
    };
    ok($response, 'Object::Response accepts cert_text without requiring cacert')
        or diag $@;
    ok($response && $response->success, 'response status is success');

    my $a = eval { $response->to_assertion };
    ok($a, 'to_assertion() succeeds using the cert_text propagated from Response')
        or diag $@;
    is($a && $a->nameid, 'lowuser@victim.com',
        'correct nameid extracted via Object::Response cert_text propagation');
}

done_testing;
