package Net::SAML2::Protocol::LogoutRequest;
use Moose;

extends 'Net::SAML2::Protocol';

# VERSION

use MooseX::Types::Common::String qw/NonEmptySimpleStr/;
use MooseX::Types::URI            qw/Uri/;
use Net::SAML2::Util              qw/xml_without_comments new_xpc/;
use XML::Generator                ();
use URN::OASIS::SAML2             qw/:urn NAMEID_PERSISTENT/;

# ABSTRACT: SAML2 LogoutRequest Protocol object

=head1 SYNOPSIS

  my $logout_req = Net::SAML2::Protocol::LogoutRequest->new(
    issuer      => $issuer,
    destination => $destination,
    nameid      => $nameid,
    session     => $session,
  );

=head1 DESCRIPTION

=head1 METHODS

=head2 my $request = $class->new(%options)

This constructor accepts all C<%options> provided by the base class
L<Net::SAML2::Procotol> constructor C<new()>.  IdP's identity URI in
C<destination> is required for a signed message but likely should be
sent regardless.

Additional options: (which are also provided as read-accessor)

=over

=item B<session> => $index (required)

The session to log out.

=item B<nameid> => $nameid (required).

NameID of the user to log out.

=back

The following options alter the output of the C<NameID> element.

=over

=item B<nameid_format> => $format

When supplied adds the C<Format> attribute to the C<NameID> element.

=item B<sp_provided_id> => $id

When supplied adds the C<SPProvidedID> attribute to the C<NameID> element.

=item B<include_name_qualifier> => $bool

Tell the module to include the C<NameQualifier> and C<SPNameQualifier> attributes in
the C<NameID> element. Defaults to false, unless the C<nameid_format> equals the urn of
C<NAMEID_PERSISTENT>.

=item B<name_qualifier> => $urn

When supplied sets the C<NameQualifier> attribute. When not supplied, this
defaults to the C<destination>.

=item B<affiliation_group_id> => $id

When supplied sets the C<SPNameQualifier> attribute. When not supplied, this
defaults to the issuer.

=back

=cut

has session       => (isa => NonEmptySimpleStr, is => 'ro', required => 1);
has nameid        => (isa => NonEmptySimpleStr, is => 'ro', required => 1);
has nameid_format => (isa => NonEmptySimpleStr, is => 'ro');
has destination   => (isa => NonEmptySimpleStr, is => 'ro');
has sp_provided_id         => (isa => NonEmptySimpleStr, is => 'ro');
has affiliation_group_id   => (isa => NonEmptySimpleStr, is => 'ro');
has name_qualifier         => (isa => NonEmptySimpleStr, is => 'ro');
has include_name_qualifier => (isa => 'Bool', is => 'ro', default => 0);

around BUILDARGS => sub {
    my ($orig, $self, %args) = @_;
    $args{include_name_qualifier} = $args{nameid_format} && $args{nameid_format} eq NAMEID_PERSISTENT;
    $self->$orig(%args);
};


=head2 my $request = $class->new_from_xml(xml => $xml, %options)

Create this object from the given XML.

Supported C<%options>:

=over

=item xml => $string (required)

XML test of the logout request.

=back

=cut

sub new_from_xml {
    my ($class, %args) = @_;

    my $xpc = new_xpc xml_without_comments $args{xml};
    my $req = $xpc->findnodes('/samlp:LogoutRequest')->shift;

    my %params = (
        id          => $xpc->findvalue('@ID', $req),
        destination => $xpc->findvalue('@Destination', $req),
        session     => $xpc->findvalue('samlp:SessionIndex', $req),
        issuer      => $xpc->findvalue('saml:Issuer', $req),
        nameid      => $xpc->findvalue('saml:NameID', $req),
        include_name_qualifier => $args{include_name_qualifier},
    );

    my $nameid_format = $xpc->findvalue('saml:NameID/@Format', $req);

    $params{nameid_format} = $nameid_format
        if NonEmptySimpleStr->check($nameid_format);

    return $class->new(%params);
}

=head2 my $xml = $request->as_xml()

Returns this LogoutRequest object as XML.

=cut

sub as_xml {
    my $self   = shift;

    my $x      = XML::Generator->new(':pretty=0');
    my $saml   = [ saml  => URN_ASSERTION ];
    my $samlp  = [ samlp => URN_PROTOCOL  ];

    my $dest   = $self->destination;
    my $format = $self->nameid_format;
    my $sspid  = $self->sp_provided_id;
    my $nameq  = $self->name_qualifier // $dest;

    return $x->xml(
        $x->LogoutRequest(
            $samlp,
            {
                ID           => $self->id,
                Version      => '2.0',
                IssueInstant => $self->issue_instant,
                $dest ? (Destination => $dest) : (),
            },
            $x->Issuer($saml, $self->issuer),
            $x->NameID(
                $saml,
                {
                    $format ? (Format => $format) : (),
                    $sspid  ? (SPProvidedID => $sspid) : (),
                    $self->include_name_qualifier
                    ? ( $nameq ? (NameQualifier => $nameq) : (),
                        SPNameQualifier => $self->affiliation_group_id // $self->issuer,
                      )
                    : (),
                },
                $self->nameid,
            ),
            $x->SessionIndex($samlp, $self->session),
        )
    );
}

__PACKAGE__->meta->make_immutable;
