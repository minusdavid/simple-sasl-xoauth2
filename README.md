# simple-sasl-xoauth2
Simple Cyrus SASL client plugin providing the XOAUTH2 mechanism.

Note that this plugin just handles the XOAUTH2 authentication process between the SASL client and the target server. The application is responsible for providing a valid OAuth2 token via the SASL_CB_PASS callback. There are lots of different ways of implementing the fetching of OAuth2 tokens.

This plugin was created to allow Postfix to use Microsoft/Google as a relayhost and authenticate using XOAUTH2. However, it can be used by any application implementing Cyrus SASL. One example is to configure Dovecot to use XOAUTH2, and send emails to Dovecot's SMTP submission service using Perl's Net::SMTP and Authen::SASL::XS. Take a look at the wiki for more information on use cases. 

## Build dependencies
```
apt install gcc make libsasl2-dev
```
These are Ubuntu 24.04 dependencies, but you should be able to find similar on most Linux distributions.

## Source install 
```
make
make install
```
The Makefile installs the plugin to either /usr/lib/sasl2/00-simple-xoauth2.so or /usr/lib/x86_64-linux-gnu/sasl2/00-simple-xoauth2.so alongside other Cyrus SASL plugins.
