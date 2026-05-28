This file lists some considerations about the transformation from the 0.85
version into 2.00.

# Changes

## Role versus 'extends'

When classes has overlapping functionality, then you can decide between
three options: (1) put the code in the base-class, (2) create a Role class,
or (3) put it as a function in a Util package.

It's a bit subjective, but the following decission tree helps:
  * when the logic is shared by a subset of your modules, which are a group by themselves, then the base class is the best place,
  * when the logic implements something like an Java 'interface' towards and external distribution, then a Role is the best choice, and
  * when the logic is ment to simplify code, put it as function in Util.

None of the existing `::Role::` packages implemented an interface so their logic
was moved elsewhere.  Base classes `Net::SAML2::Protocol` and `Net::SAML2::Binding`
were created.

## `XML::LibXML::XPathContext`

This object was created on many places, and everywhere the prefixes were set again,
with the chance of missing prefixes and other mistakes.

Method `::Util::new_xpc()` generated a standard configuration.

## Predicate `has_attribute` lies

The old code expected that a true for `has_xyz` ment that `xyz`
had a correct value, where it only means the parameter was passed at
instantiation of the object.

Especially, there were a few sleeping bugs with attributes containing
an ARRAY.  In most cases, `list => undef` and `list => []`, both mean
that the list is empty.  In the latter case, `has_list` is true.

Rewrote all use of predicates.  In above case
```perl
if($self->has_list) { print @{$self->list} }
```
became
```perl
my $list = $self->list // [];
print @$list if @$list;
```
Or better
```perl
has list => (..., default => sub {[]});
print @{$self->list};  # print() with empty does nothing
```

## `XML::Sig` interface to `Net::SAML2::XML::Sig`

`Net::SAML2::XML::Sig` is very usefull to bridge the problems with
`XML::Sig` with the main modules.  All quirks have moved there
now.

The only problem, it seems, is that `XML::Sig` produces the signature
on the wrong location.  According to the SAML2 spec, it must be
right behind the Issuer, hence as second child in the container.

## Documentation

The docs where very incomplete and inconsistent.  Now, it's not
producing my preferred manuals, but at least they became complete
and consistent in style.

In many places, HASH is confused with PAIRS, and ARRAY and array
with LIST.

For comparison
```perl
  $obj->call(%params);    # passed as LIST containing PAIRS
  $obj->call(\%params);   # passed as LIST with one HASH
  $obj->call(@values);    # passed a LIST of values from the array
  $obj->call(\@values);   # passes one array reference: an ARRAY

  print @values;          # prints a LIST of values, source from an array
  my ($a, $b) = (1, 2);   # LIST assignment
  my @values  = (1, 2);   # LIST assignment into an array
  print Dumper \@v;       # prints the Dumper of an ARRAY
```

# Possible improvements, not taken (yet)

## die, croak, confess

Internal errors can best case a `confess` (`croak` with stack-trace).
Some `die` uses are probably `croak` of `confess`.

## Parsing and creating XML all the time

In many places, XML is being constructed, then stringified to call
a function, then parsed again.  This is pretty clumsy and slows down
processing.  Part of the problem is that `XML::Generator` is used to
create XML, and `XML::LibXML` to read it.

Shameless plug: SAML2 has a schema, so `XML::Compile::Schema` would
make your life very, very simple.

## Package renames

Backwards compatibility breaking:
```
  Net::SAML2::Protocol::Artifact --> Net::SAML2::Protocol::ArtifactResponse
  Net::SAML2::Protocol::ArtifactResolve --> Net::SAML2::Protocol::ArtifactRequest
  Net::SAML2::Protocol::Assertion --> Net::SAML2::Protocol::AssertionRequest
  Net::SAML2::Object::Response -> Net::SAML2::Protocol::AssertionResponse
```
They cannot easily be renamed, because the published interface of Net::SAML2
uses explicit package names everywhere.

## ::Protocol --> ::Message

I think that one of the reasons that `Net::SAML2::Role::ProtocolMessage` existed,
is confusion about ::Protocol::  The modules, like `Net::SAML2::Protocol::AuthnRequest`
do *not* implement the protocol: they implement messages.  Together, the messages
implement the protocol.

These packages usually implement both `new_from_xml()` and `as_xml()` (some are missing!)
which is nice for debugging: you can go both ways.

## Removing Moose

Moose is rarely helpfull in generic modules.  It requires the installation
(and run-time inclusion) of a zillions of packages, and might conflict
with the OO extension system that the application is using (like Moo,
Mouse, etc).  When you create a end-user application, then it might be
the better choice.

Removal of Moose is not difficult.

## Documentation

When the objects are larger, then you feel the need to group methods into document sections.
For instance, sections `Constructors`, `Attributes`, and `Deprecated interface`.

This is now not possible, because each method uses a `=head2`; it should become `=head3` globally.

## Reparsing of certificates and keys

Probably, it helps to read certificate and key source on the moment the object
is created.  Or, at least, cache their results.

# Future plans

## `Net::SAML2::Client`

The older interface of `Net::SAML2` requires the use of long path names for
message classes.  This is really inconvenient.

Apparently, I am not the only one with that feeling so later simplifications
were added via Net::SAML2::SP.
```perl
  my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
     issuer        => $sp->issuer,
     destination   => $sso_url,
     provider_name => $provider_name,
  );

  my $req = $sp->authn_request($sso_url, NAMEID_PERSISTENT, provider_name => $pname);
```
However: SP is *not* the right location.  It does simplify the code a bit, mainly
by hiding awkward long explicit package paths, but this functionality is *not* the
task of the SP object.  The SP object (see attributes) is about grouping SP information,
not implementing the protocol.

The correct location is a new `Net::SAML2::Client`.
```perl
  my $saml = Net::SAML2::Client->new(
     service_provider  => $sp,
     identity_provider => $idp,
  );

  $saml->connect(...)
     or die "Failed to login";

  my $user_id = $saml->authenticate(...)
     or die "User not known";
```
