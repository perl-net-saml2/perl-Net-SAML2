# Saml2Test Application

The Saml2Test application was created to allow the developers to test a SAML2 Service Provider (SP) application against an Identity Provider (IdP).  The application allows you to:

   1. Produce a SP metadata.xml that can be uploaded to an Identity Provider
   2. Login via a SAML2 AuthnRequest
   3. Access user attributes provided in the SAML2 Assertion
   3. Logout via a SAML2 LogoutRequest

## Required Steps

### Create host file entry

The config.yml is configured for the testapp to be available at: https://netsaml2-testapp.local.  Add the following to your /etc/hosts entry (or the equivalent on windows).

127.0.0.1   netsaml2-testapp.local   netsaml2-testapp

### Generate new Service Provider (SP) signing Key and Certificate

This is optional - you can generate your own certificates or use the existing certificates from the git repository.

   1. openssl req -x509 -nodes -newkey rsa:4096 -keyout sign-private.pem -out sign-certonly.pem -days 36500
   2. cat sign-certonly.pem sign-private.pem > sign-nopw-cert.pem

### Start the Saml2Test application

   1. cd xt/testapp
   2. perl Saml2Test.pl

The application starts and accepts browser connections on port 3000:

Access http://localhost:3000

### Run lighttpd to proxy https to the Saml2Test application

Many SAML2 Identity Providers will not allow the application (Service Provider) URL to be http and forces you to specify https to use SAML2.  lighttpd is used to listen on port 443 and use https protocol so that the Identity Provider can redirect or POST to a https site.  lighttpd then proxies that communication to the Dancer application listening on port 3000.

   1. cd xt/testapp
   2. sudo lighttpd -D -f lighttpd.conf

Note that the command requires sudo to allow it to use the default https port of 443.

TODO: maybe change it to use 8443

### Configure the testapp to connect to the Identity Provider

The testapp now supports a simplified automatic configuration for testing against multiple Identity Providers (IdPs).

   1. Simply create a directory in xt/testapp/IdPs for the name of the IdP (eg. google)
   2. Download the metadata from your IdP and save it as IdPs/google/metadata.xml
   3. Download the cacert.pem from the IdP and save it as IdPs/google/cacert.pem
   4. Optionally create IdPs/google/config.yml for custom settings for the IdP (if the a custom config.yml does not exist it will refresh the settings from the default config.yml.

The index page will automatically list each configured Identity Provider as a link to initiate login against that IdP.

Your directory structure should look like:

IdPs/
    auth0/
        cacert.pem
        metadata.yml
    azure/
        cacert.pem
        config.yml (optional)
        metadata.yml
    google/
        cacert.pem
        metadata.yml

### Run lighttpd to deliver metadata.xml

Net::SAML2 requires access to a URL containing the metadata.  The simplest method to provide this is to run the provided lighttpd-metadata.conf file:

   1. cd xt/testapp
   2. lighttpd -D -f lighttpd-metadata.conf

The metadata has been configured to be available at: http://localhost:8880/metadata.xml.  The simplified IdP configuration will automatically access the metadata.xml at http://localhost:8880/IdPs/google/metadata.xml (if you followed the instructions above and created the google directory in xt/testapp/IdPs)

Note that the configuration attempts to only deliver a file named metadata.xml from the xt/testapp directory.  There are no guarantees - this is a test application so verify your own security.

### Access the testapp to download the application metadata

Saml2Test provides a metadata.xml for the Application that can be used to upload to the Identity Provider to make the configuration simpler.

   1. Access http://localhost:3000
   2. Click *SP Metadata* to download the metadata.xml
   3. Save the metadata.xml file for upload to the Identity Provider

### Configure your Identity Provider

Depending on the Identity Provider this can range from simple to easy.  For testing purposes most Identity Providers will provide a free developer account.  Some require you to define users first, others will simply allow you to use whatever your admin user is as a SAML user.

If there is an option to upload the metadata.xml that is probably your first step as it will set most configuration items properly for you.

Saml2Test expects the Identity Provider to provide an assertion with the following values:

   1. DN
   2. CN
   3. EmailAddress
   4. FirstName
   5. Address
   6. Phone
   7. EmployeeNumber

Note that DN and CN (and others) may not be available.  That can be customized in views/user.tt if you want to choose other options.  However the Identity Provider must provide the assertion attributes that match the expected names in views/user.tt.

## Debugging

If you are making changes to Net::SAML2 and want to use the Saml2Test to test those changes do the following:

   1. Make the changes as required in Net::SAML2
   2. perl Makefile.PL
   3. make
   4. cd xt/testapp
   5. perl -I ../../blib/lib/ -I ../../blib/arch/ Saml2Test.pl

That allows you to test against the version of Net::SAML2 that you are modifying.  Note that Dancer caches the version it started with including the Net::SAML2 module so you will need to restart Saml2Test.pl to test the changes you made.
