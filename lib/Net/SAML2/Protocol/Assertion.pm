package Net::SAML2::Protocol::Assertion;
use Moose;

extends 'Net::SAML2::Protocol';

# VERSION

use MooseX::Types::DateTime       qw/DateTime/;
use MooseX::Types::Common::String qw/NonEmptySimpleStr/;

use Carp                   qw/croak/;
use List::Util             qw/first/;
use Net::SAML2::Util       qw/xml_without_comments new_xpc/;
use URN::OASIS::SAML2      qw/STATUS_SUCCESS/;

use DateTime               ();
use DateTime::HiRes        ();
use DateTime::Format::XSD  ();
use Net::SAML2::XML::Sig   ();
use XML::Enc               ();

# ABSTRACT: SAML2 assertion object

=head1 SYNOPSIS

  my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
    xml => decode_base64($SAMLResponse),
  );

=head1 DESCRIPTION

=head1 METHODS

=head2 my $assert = $class->new(%options)

Create a new Assertion object.  You probably want to use C<new_from_xml()>
to configure the C<%options>.

All options provided by the base class L<Net::SAML2::Protocol> constructor
C<new()> are supported, with the C<in_response_to> required.

More C<%options>: (which also have read accessors)

=over 4

=item B<attributes> => HASH-of-ARRAYS

=item B<audience> => $string (required)

=item B<not_after> => DateTime object (required)

=item B<not_before> => DateTime object (required)

=item B<session> => $index (required)

=item B<response_status> => $string (required)

=item B<response_substatus> => $string

SAML errors are usually "nested" ("Responder -> RequestDenied" for instance,
means that the responder in this transaction (the IdP) denied the login
request). For proper error message generation, both levels are needed.

=back

=cut

has '+in_response_to' => (required => 1);
has attributes      => (isa => 'HashRef[ArrayRef]', is => 'ro', required => 1);
has audience        => (isa => NonEmptySimpleStr, is => 'ro', required => 1);
has not_after       => (isa => DateTime,          is => 'ro', required => 1);
has not_before      => (isa => DateTime,          is => 'ro', required => 1);
has session         => (isa => 'Str', is => 'ro', required => 1);
has response_status => (isa => 'Str', is => 'ro', required => 1);
has response_substatus => (isa => 'Str', is => 'ro');

has nameid_object => (
    isa       => 'XML::LibXML::Element',
    is        => 'ro',
    init_arg  => 'nameid',
);

has authnstatement_object => (
    isa       => 'XML::LibXML::Element',
    is        => 'ro',
    init_arg  => 'authnstatement',
);


=head2 my $assert = $class->new_from_xml(xml => $string, %options)

Constructor. Creates an Assertion object, parsing the given XML to find
the attributes, session, and nameid.

All parameters which are required for C<new()> are extracted from
the provided xml.  You have these C<%options> here:

=over

=item xml => $string (required)

XML string.

=item key_file => $filename

Required only when handling Encrypted Assertions.

Path to the SP's private key file that matches the SP's public certificate
used by the IdP to Encrypt the response (or parts of the response)

=item cacert => $filename

Path to the CA certificate for verification.  This is only used for
validating the certificate provided for a signed C<Assertion> that was
found when the C<EncryptedAssertion> is decrypted.

While optional it is recommended for ensuring that the C<Assertion> in an
C<EncryptedAssertion> is properly validated.

=back

=cut

sub _verify_encrypted_assertion {
    my ($self, $xml, $cacert, $key_file, $key_name) = @_;

    my $xpc = new_xpc $xml;
    $xpc->exists('//saml:EncryptedAssertion')
        or return $xml;

    defined $key_file
        or croak "Encrypted Assertions require key_file";

    $xml = $self->_decrypt($xml, key_file => $key_file, key_name => $key_name);
    $xpc->setContextNode($xml);

    my $assert = $xpc->findnodes('//saml:Assertion')->shift
        or return $xml;

    $xpc->exists('ds:Signature', $assert)
        or return $xml;

    my $signer = Net::SAML2::XML::Sig->new(no_xml_declaration => 1);
    $signer->verify($assert->toString)
        or die "Decrypted Assertion signature check failed";

    $cacert
        or return $xml;

    my $cert = $signer->signer_cert
        or die "Certificate not provided in SAML Response, cannot validate";

    my $ca = Crypt::OpenSSL::Verify->new($cacert, { strict_certs => 0 });
    $ca->verify($cert)
        or die "Unable to verify signer cert with cacert: " . $cert->subject;

    return $xml;
}

sub new_from_xml {
    my ($class, %args) = @_;

    my $key_file = $args{key_file};
    my $key_name = $args{key_name};
    my $cacert   = delete $args{cacert};
    my $xml      = xml_without_comments $args{xml};

    $xml         = $class->_verify_encrypted_assertion($xml, $cacert, $key_file, $key_name);

    #XXX _decrypt is called again: also within the previous call. Nothing to do?
    my $dec      = $class->_decrypt($xml, key_file => $key_file, key_name => $key_name);
    my $xpc      = new_xpc $dec;

    my %attributes;
    for my $node ($xpc->findnodes('//saml:Assertion/saml:AttributeStatement/saml:Attribute/saml:AttributeValue/..'))
    {
        my @values = $xpc->findnodes('saml:AttributeValue', $node);
        $attributes{$node->getAttribute('Name')} = [ map $_->string_value, @values ];
    }

    my $conditions = '//samlp:Response/saml:Assertion/saml:Conditions/';

    my $not_before;
    if (my $value = $xpc->findvalue($conditions . '@NotBefore')) {
        $not_before = DateTime::Format::XSD->parse_datetime($value);
    }
    elsif (my $global = $xpc->findvalue('//saml:Conditions/@NotBefore')) {
        $not_before = DateTime::Format::XSD->parse_datetime($global);
    }
    else {
        $not_before = DateTime::HiRes->now();
    }

    my $not_after;
    if(my $value = $xpc->findvalue($conditions . '@NotOnOrAfter')) {
        $not_after = DateTime::Format::XSD->parse_datetime($value);
    }
    elsif(my $global = $xpc->findvalue('//saml:Conditions/@NotOnOrAfter')) {
        $not_after = DateTime::Format::XSD->parse_datetime($global);
    }
    else {
        $not_after = DateTime->from_epoch(epoch => time() + 1000);
    }

    my $nameid
      = $xpc->findnodes('/samlp:Response/saml:Assertion/saml:Subject/saml:NameID')->shift
     || $xpc->findnodes('//saml:Subject/saml:NameID')->shift;

    my $authnstatement = $xpc->findnodes('/samlp:Response/saml:Assertion/saml:AuthnStatement')->shift;

    my $status_node = $xpc->findnodes('/samlp:Response/samlp:Status/samlp:StatusCode|/samlp:ArtifactResponse/samlp:Status/samlp:StatusCode')->shift
        or croak "Unable to parse status from assertion";
    my $status      = $status_node->getAttribute('Value');

    my $substatus;
    if(my $s = first { $_->isa('XML::LibXML::Element') } $status_node->childNodes) {
        $substatus = $s->getAttribute('Value');
    }

    return $class->new(
        id              => $xpc->findvalue('//saml:Assertion/@ID'),
        issuer          => $xpc->findvalue('//saml:Assertion/saml:Issuer'),
        destination     => $xpc->findvalue('/samlp:Response/@Destination'),
        attributes      => \%attributes,
        session         => $xpc->findvalue('//saml:AuthnStatement/@SessionIndex'),
        audience        => $xpc->findvalue('//saml:Conditions/saml:AudienceRestriction/saml:Audience'),
        not_before      => $not_before,
        not_after       => $not_after,
        in_response_to  => $xpc->findvalue('//saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo'),
        response_status => $status,
        $nameid         ? (nameid => $nameid) : (),
        $substatus      ? (response_substatus => $substatus) : (),
        $authnstatement ? (authnstatement => $authnstatement) : (),
    );
}

=head2 my $name = $assert->name()

Returns the CN attribute, if provided.

=cut

sub name { return shift->attributes->{CN}[0] }

=head2 my $nameid = $assert->nameid()

Returns the NameID.

=cut

sub nameid {
    my $self   = shift;
    my $nameid = $self->nameid_object;
    return $nameid ? $nameid->textContent : undef;
}

=head2 my $format = $assert->nameid_format()

Returns the NameID Format.

=cut

sub nameid_format {
    my $self   = shift;
    my $nameid = $self->nameid_object;
    return $nameid ? $nameid->getAttribute('Format') : undef;
}

=head2 my $qual = $assert->nameid_name_qualifier()

Returns the NameID NameQualifier

=cut

sub nameid_name_qualifier {
    my $self   = shift;
    my $nameid = $self->nameid_object;
    return $nameid ? $nameid->getAttribute('NameQualifier') : undef;
}

=head2 my $qual = $assert->nameid_sp_name_qualifier()

Returns the NameID SPNameQualifier.

=cut

sub nameid_sp_name_qualifier {
    my $self   = shift;
    my $nameid = $self->nameid_object;
    return $nameid ? $nameid->getAttribute('SPNameQualifier') : undef;
}

=head2 my $spid = $assert->nameid_sp_provided_id()

Returns the NameID SPProvidedID

=cut

sub nameid_sp_provided_id {
    my $self = shift;
    my $nameid = $self->nameid_object;
    return $nameid ? $nameid->getAttribute('SPProvidedID') : undef;
}

=head2 my $stm = $assert->authnstatement()

Returns the AuthnStatement xml content as text.

=cut

sub authnstatement {
    my $self = shift;
    my $auth = $self->authnstatement_object;
    return $auth ? $auth->textContent : undef;
}

=head2 my $inst = $assert->authnstatement_authninstant()

Returns the AuthnStatement attribute AuthnInstant.

=cut

sub authnstatement_authninstant {
    my $self = shift;
    my $auth = $self->authnstatement_object;
    return $auth ? $auth->getAttribute('AuthnInstant') : undef;
}

=head2 my $index = $assert->authnstatement_sessionindex()

Returns the AuthnStatement attribute SessionIndex.

=cut

sub authnstatement_sessionindex {
    my $self = shift;
    my $auth = $self->authnstatement_object;
    return $auth ? $auth->getAttribute('SessionIndex') : undef;
}

=head2 my $subj = $assert->authnstatement_subjectlocality()

Returns the AuthnStatement node SubjectLocality.

=cut

sub authnstatement_subjectlocality {
    my $self = shift;
    my $auth = $self->authnstatement_object or return;
    return new_xpc($auth)->findnodes('//saml:AuthnStatement/saml:SubjectLocality')->shift;
}

=head2 my $address = $assert->subjectlocality_address()

Returns the SubjectLocality attribute Address.

=cut

sub subjectlocality_address {
    my $self = shift;
    my $subjectlocality = $self->authnstatement_subjectlocality;
    return $subjectlocality ? $subjectlocality->getAttribute('Address') : undef;
}

=head2 my $hostname = $assert->subjectlocality_dnsname()

Returns the SubjectLocality attribute DNSName.

=cut

sub subjectlocality_dnsname {
    my $self = shift;
    my $subjectlocality = $self->authnstatement_subjectlocality;
    return $subjectlocality ? $subjectlocality->getAttribute('DNSName') : undef;
}

=head2 my $ctx = $assert->authnstatement_authncontext()

Returns the AuthnContext node for the AuthnStatement.

=cut

sub authnstatement_authncontext {
    my $self = shift;
    my $auth = $self->authnstatement_object or return;
    return $self->{authnctx} ||=
        new_xpc($auth)->findnodes('//saml:AuthnStatement/saml:AuthnContext')->shift;
}

=head2 my $ctx = $assert->contextclass_authncontextclassref()

Returns the ContextClass AuthnContextClassRef.

=cut

sub contextclass_authncontextclassref {
    my $self = shift;
    my $auth = $self->authnstatement_object or return;
    my $authncontextclassref = $self->authnstatement_authncontext or return;

    my $xpc = new_xpc $auth;
    if(my $value = $xpc->findvalue('//saml:AuthnContextClassRef')) {
        return $value;
    }

    return $authncontextclassref;   #XXX fishy.  Return undef?
}

=head2 $assert->valid($audience, $in_response_to)

Returns true if this Assertion is currently valid for the given audience.

Also accepts C<$in_response_to> (optional), which it checks against the
returned Assertion.  This is very important for security as it helps
ensure that the assertion that was received was for the request that
was made.

Checks the audience matches, and that the current time is within the
Assertions validity period as specified in its Conditions element.

=cut

sub valid {
    my ($self, $audience, $in_response_to) = @_;

    defined $audience && $audience eq $self->audience
        or return 0;

    !defined $in_response_to || $in_response_to eq $self->in_response_to
        or return 0;

    my $now = DateTime::HiRes->now;

    # not_before is "NotBefore" element - exact match is ok
    # not_after is "NotOnOrAfter" element - exact match is *not* ok
    return DateTime->compare($now, $self->not_before) > -1
       && DateTime->compare($self->not_after,  $now) > 0 ? 1 : 0; #XXX tests require false=0
}

=head2 my $found = $assert->success

Returns true if the response status is a success, returns false otherwise.
In case the assertion isn't successfull, the L</response_status> and L</response_substatus> calls can be use to see why the assertion wasn't successful.

=cut

sub success { return shift->response_status eq STATUS_SUCCESS }

sub _decrypt {
    my ($self, $xml, %options) = @_;

    my $key_file = $options{key_file}
        or return $xml;

    my $enc = XML::Enc->new({ no_xml_declaration => 1, key => $key_file });
    return XML::LibXML->load_xml(string => $enc->decrypt($xml, %options));
}

1;
