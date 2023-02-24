use strict;
use warnings;
use Test::More;
use Selenium::Chrome;
use Selenium::Waiter qw(wait_until);
use FindBin          qw( $RealBin );
use File::Slurper qw/ read_dir /;
use File::Spec::Functions  qw/catfile/;
use File::Path qw( make_path );
use YAML;

=head2 Selenium setup

=over

=item * L<Module>

cpanm Selenium::Chrome

=item * L<chromedriver>

Download chromedriver (https://chromedriver.chromium.org/downloads) extract
and copy to ~/perl-Net-SAML2/xt/testapp/t/selenium

export set PATH=$PATH:~/perl-Net-SAML2/xt/testapp/t/selenium; perl t/004_selenium.t

=back

=head2 Configuration

Each IdP is set up in xt/testapp/IdPs/idp_name.  This script requires
the existance of a configuration file named selenium.yml.

The following fields are supported.  Not all IdPs need the full list
of configuration fields.

=over

=item * L<username>

The username to be entered into the IdP

=item * L<username_fn>

The identifier used to find the username field on the IdP login page

=item * L<username_by>

The method used to find the "username_fn" on the IdP login page. The supported
methods are: class, class_name, css, id, link, link_text, partial_link_text,
tag_name, name, xpath.

=item * L<separate_passwd_page>

Boolean that specifies whether the IdP has implemented the username and password
as separate pages.

=item * L<password>

The password to be entered into the IdP

=item * L<password_fn>

The identifier used to find the password field on the IdP login page

=item * L<password_by>

The method used to find the "password_fn" on the IdP login page. The supported
methods are: class, class_name, css, id, link, link_text, partial_link_text,
tag_name, name, xpath.

=item * L<login_btn>

The identifier used to find the login button on th IdP's login page.  It is assumed
that "clicking" the button will submit the username and/or password.

Note that where there are separate username and password pages the same button
identifier is assumed to be the same.

=item * L<login_btn_by>

The method used to find the "login_btn" on the IdP login page. The supported
methods are: class, class_name, css, id, link, link_text, partial_link_text,
tag_name, name, xpath.

=item * L<post_login_page_title>

Some IdPs provide a web page that is displayed after login and this allows the
script to recoginize the page and move past it.

=item * L<post_login_page_btn>

The identifier used to find a button on the IdP's post login page.  It is assumed
that "clicking" the button will move on to the NetSAML2 testapp's logged in page.

=item * L<post_login_page_btn_by>

The method used to find the "post_login_page_btn" on the IdP login page. The supported
methods are: class, class_name, css, id, link, link_text, partial_link_text,
tag_name, name, xpath.

=item * L<post_logout_page_title>

Some IdPs provide a web page that is displayed after logout and this allows the
script to recoginize the page and move past it to the Net::SAML2 testapp login page.

=item * L<login_bindings>

Array of login bindings that the IdP supports (supported are: post, redirect).

=item * L<logout_bindings>

Array of logout bindings that the IdP supports (supported are: local, post, redirect).

=item * L<issuer_value>

Value of the issuer to find on the user logged in page for Net::SAML2 testapp to
confirm that the login worked

=back

=cut
if (! -d "$RealBin/selenium" ) {
    print "Created directory $RealBin/selenium\n" if (make_path("$RealBin/selenium"));
}

if (! -e -f "$RealBin/selenium/chromedriver") {
    BAIL_OUT("Please ensure that the chromedriver binary is in $RealBin/selenium/");
}

my $driver =  Selenium::Chrome->new(
                        binary => "$RealBin/selenium/chromedriver",
                        accept_ssl_certs  => 1,
                        );

isa_ok($driver, 'Selenium::Chrome');

my $ret = $driver->get('https://netsaml2-testapp.local');
if ( $driver->get_title ne 'Saml2Test' ) {
    $driver->quit;
    BAIL_OUT("Unable to access https://netsaml2-testapp.local");
}

ok($ret, "Access https://netsaml2-testapp.local");

##############################################
# FIXME: Get this based on the list in IdPs
##############################################

ok ( -d -e 'IdPs', "'IdPs' directory exists");

my @idps = load_idps();

##############################################
# Loop through each of the IdPs being tested
##############################################
foreach my $idp (@idps) {
    subtest "Authenticate and logout at each IdP - $idp" => \&auth_to_idp, $idp;
}

$driver->quit;

sub auth_to_idp {
    my $idp = shift;

    note "==============================================\n";
    note "= Beginning test for IdP: $idp\n";
    note "==============================================\n";
    # Load the IdP configuration file
    my $config_file = catfile( 'IdPs', $idp, 'selenium.yml' );
    if ( ! -e $config_file ) {
        plan skip_all => "$config_file does not exist";
        next;
    }
    ok (defined $config_file, "selenium config file found for $idp");

    my $selenium_config = YAML::LoadFile($config_file);

    if ( ! $selenium_config ) {
        plan skip_all => "Check format of $config_file";
    }
    ok ($selenium_config, "Loaded selenium config from $config_file");

    ############################################
    # Loop through each of the logout bindings
    ############################################
    foreach my $logout_binding (@{$selenium_config->{"logout_bindings"}}) {
        note "Logout: ", $logout_binding, "\n";

        ############################################
        # Loop through each of the login bindings
        # for each of the logout bindings in turn
        ############################################
        foreach my $login_binding (@{$selenium_config->{"login_bindings"}}) {
            note "----------------------------------------------\n";
            note "    Login: $login_binding", "\n";

            # The Net::SAML2 testapp has the 'id' set for each of
            # the redirect links and POST buttons (ex: keycloak_post)
            # Find the link or button and "click" on it.
            my $login_id = $idp . "_" . $login_binding;
            my $link = wait_until{$driver->find_element($login_id, "id")};
            ok($link, "Found login element for: $login_id");
            next if ( ! $link );
            $link->click('left');

            # If you click login and immediately get a Saml2Test webpage
            # it means the IdP logged you in automatically.  The last
            # login session was still considered active.
            if ($driver->get_title ne 'Saml2Test') {
                # Find the username field and enter the username
                my $username = wait_until{$driver->find_element(
                                                $selenium_config->{"username_fn"},
                                                (defined $selenium_config->{"username_by"} ?
                                                $selenium_config->{"username_by"} : "id"
                                                ))};
                ok($username, "Found username field: $selenium_config->{'username_fn'}");

                next if ( ! $username && $logout_binding ne 'local');

                $username->send_keys($selenium_config->{'username'});

                # If the IdP has separate username and password pages
                # submit the username first
                if ($selenium_config->{"separate_passwd_page"}) {
                    # Find the login button and click it
                    my $login = wait_until{$driver->find_element(
                                                $selenium_config->{"login_btn"},
                                                $selenium_config->{"login_btn_by"})};
                    ok($login, "Found login continue button: $selenium_config->{'login_btn'}");
                    next if ( ! $login);

                    $login->click('left');
                }

                # Find the password field and enter the password
                my $password = wait_until{$driver->find_element(
                                                $selenium_config->{"password_fn"},
                                                defined $selenium_config->{"password_by"} ?
                                                $selenium_config->{"password_by"} : "id"
                                                )};
                ok($password, "Found password field: $selenium_config->{'password_fn'}");
                next if ( ! $password );

                $password->send_keys($selenium_config->{'password'});

                # Find the login button and click it
                my $login = wait_until{$driver->find_element(
                                                $selenium_config->{"login_btn"},
                                                $selenium_config->{"login_btn_by"})};
                ok($login, "Found login button: $selenium_config->{'login_btn'}");
                next if ( ! $login);

                $login->click('left');

                # Check for a post login IdP page and click the continue button
                if ( defined $selenium_config->{"post_login_page_title"} &&
                                $driver->get_title eq $selenium_config->{"post_login_page_title"} )
                {
                    note "Found post login page - continuing\n";
                    my $proceed = wait_until{$driver->find_element(
                                                $selenium_config->{"post_login_page_btn"},
                                                $selenium_config->{"post_login_page_btn_by"})};
                    ok($proceed, "Found post login proceed button: $selenium_config->{'post_login_page_btn'}");
                    next if ( ! $proceed );
                    $proceed->click('left');
                }
            } else {
                # The IdP automatically logged in the user - it considered
                # the last session as still active.
                note "    Automatically logged in!!!\n"
            }
            note "    Login Complete\n";

            # Check the value of the issuer if issuer_value is defined in the config
            my $value = wait_until{$driver->find_element("issuer", "id")};
            if ( defined $selenium_config->{"issuer_value"} ) {
                ok ($selenium_config->{"issuer_value"} eq $value->get_text(), "Login confirmed: $selenium_config->{'issuer_value'} found");
            }

            note "    Logout using: $logout_binding", "\n";
            # Find the logout link or post button and click it
            my $logout = wait_until{$driver->find_element("logout-$logout_binding", "id")};
            ok($logout, "Found logout element: logout-$logout_binding");
            $logout->click('left');

            # Check for post logout page and open https://netsaml2-testapp.local
            # so that the next login can proceed
            if ( defined $selenium_config->{"post_logout_page_title"} && $driver->get_title eq $selenium_config->{"post_logout_page_title"} ) {
                note "    Found post logout - open https://netsaml2-testapp.local\n";
                $driver->get('https://netsaml2-testapp.local');
                if ( $driver->get_title ne 'Saml2Test' ) {
                    $driver->quit;
                    BAIL_OUT("Unable to access https://netsaml2-testapp.local");
                }
            }
        }
        note "==============================================\n";
    }
};

sub load_idps {
    if ( ! -x 'IdPs' ) {
        return "<html><pre>You must have a xt/testapp/IdPs directory</pre></html>";
    }
    my @dirs = read_dir('IdPs');

    my @idps;
    for my $dir (sort @dirs) {
        push (@idps, $dir) if ( -d catfile("IdPs", $dir) );
    }

    return @idps;
}
done_testing;
