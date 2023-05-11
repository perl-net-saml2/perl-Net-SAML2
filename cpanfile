# Do not edit this file directly. To change prereqs, edit the `dist.ini` file.

requires "Carp" => "0";
requires "Crypt::OpenSSL::Bignum" => "0";
requires "Crypt::OpenSSL::RSA" => "0";
requires "Crypt::OpenSSL::Random" => "0";
requires "Crypt::OpenSSL::Verify" => "0";
requires "Crypt::OpenSSL::X509" => "0";
requires "DateTime" => "0";
requires "DateTime::Format::XSD" => "0";
requires "DateTime::HiRes" => "0";
requires "Digest::MD5" => "0";
requires "Exporter" => "0";
requires "File::Slurper" => "0";
requires "HTTP::Request::Common" => "0";
requires "IO::Compress::RawDeflate" => "0";
requires "IO::Uncompress::RawInflate" => "0";
requires "LWP::Protocol::https" => "0";
requires "LWP::UserAgent" => "0";
requires "List::Util" => "0";
requires "MIME::Base64" => "0";
requires "Moose" => "0";
requires "Moose::Role" => "0";
requires "MooseX::Types" => "0";
requires "MooseX::Types::Common::String" => "0";
requires "MooseX::Types::DateTime" => "0";
requires "MooseX::Types::Moose" => "0";
requires "MooseX::Types::URI" => "0";
requires "Try::Tiny" => "0";
requires "Types::Serialiser" => "0";
requires "URI" => "0";
requires "URI::Encode" => "0";
requires "URI::Escape" => "0";
requires "URI::QueryParam" => "0";
requires "URN::OASIS::SAML2" => "0.003";
requires "XML::Enc" => "0.05";
requires "XML::Generator" => "1.13";
requires "XML::LibXML" => "0";
requires "XML::LibXML::XPathContext" => "0";
requires "XML::Sig" => "0.52";
requires "XML::Writer" => "0.625";
requires "base" => "0";
requires "namespace::autoclean" => "0";
requires "perl" => "5.012";
requires "strict" => "0";
requires "vars" => "0";
requires "warnings" => "0";

on 'test' => sub {
  requires "Import::Into" => "0";
  requires "Path::Tiny" => "0";
  requires "Sub::Override" => "0";
  requires "Test::Deep" => "0";
  requires "Test::Exception" => "0";
  requires "Test::Fatal" => "0";
  requires "Test::Lib" => "0";
  requires "Test::Mock::One" => "0";
  requires "Test::More" => "0";
  requires "Test::NoTabs" => "0";
  requires "Test::Pod" => "1.14";
  requires "Test::Pod::Coverage" => "1.04";
  requires "URI::URL" => "0";
  requires "XML::LibXML::XPathContext" => "0";
};

on 'configure' => sub {
  requires "ExtUtils::MakeMaker" => "0";
};

on 'develop' => sub {
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Test::EOF" => "0";
  requires "Test::EOL" => "0";
  requires "Test::More" => "0.88";
  requires "Test::NoTabs" => "0";
  requires "Test::Perl::Critic" => "0";
  requires "Test::Pod" => "1.41";
  requires "Test::Pod::Coverage" => "1.08";
};
