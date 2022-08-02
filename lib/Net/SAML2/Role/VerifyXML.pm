package Net::SAML2::Role::VerifyXML;
use Moose::Role;
# VERSION

use Net::SAML2::XML::Sig;
use Crypt::OpenSSL::Verify;

# ABSTRACT: A role to verify the SAML response XML

=head1 DESCRIPTION

=head1 SYNOPSIS

    use Net::SAML2::Some::Module;

    use Moose;
    with 'Net::SAML2::Role::VerifyXML';

    sub do_something_with_xml {
        my $self = shift;
        my $xml  = shift;

        $self->verify_xml($xml,
            # Most of these options are passed to Net::SAML2::XML::Sig, except for the
            # cacert
            # Most options are optional
            cacert    => $self->cacert,
            cert_text => $self->cert,
            no_xml_declaration => 1,
        );
    }

=cut


=head1 METHODS

=head2 verify_xml($xml, %args)

    $self->verify_xml($xml,
        # Most of these options are passed to Net::SAML2::XML::Sig, except for the
        # cacert
        # Most options are optional
        cacert    => $self->cacert,
        cert_text => $self->cert,
        no_xml_declaration => 1,
    );

=cut

sub verify_xml {
    my $self = shift;
    my $xml  = shift;
    my %args = @_;

    my $cacert   = delete $args{cacert};

    my $x = Net::SAML2::XML::Sig->new({
        x509      => 1,
        exclusive => 1,
        %args,
    });

    die "XML signature check failed\n" unless $x->verify($xml);

    return unless $cacert;

    my $cert = $x->signer_cert
        or die "Certificate not provided in SAML Response, cannot validate\n";

    my $ca = Crypt::OpenSSL::Verify->new($cacert, { strict_certs => 0 });
    return if $ca->verify($cert);
    die "Could not verify CA certificate!\n";
}


1;

__END__

