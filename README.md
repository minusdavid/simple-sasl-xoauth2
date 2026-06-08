# simple-sasl-xoauth2
Simple SASL plugin providing XOAUTH2 mechanism

Development
apt install gcc make libsasl2-dev

Testing
apt install libauthen-sasl-xs-perl libio-socket-ssl-perl

make
cc -fPIC -I/usr/include/sasl -Wall -O2 -o 00-simple-xoauth2.so xoauth2.c -shared -lsasl2

make install
install -m 755 00-simple-xoauth2.so /usr/lib/x86_64-linux-gnu/sasl2
Installed 00-simple-xoauth2.so to /usr/lib/x86_64-linux-gnu/sasl2



Testing Microsoft with Postfix
vi /etc/postfix/main.cf

Update relayhost to the following:
relayhost = [smtp.office365.com]:587

Update inet_protocols to the following:
inet_protocols = ipv4

Add the following to the bottom of the configuration file:
smtp_sender_dependent_authentication = yes
sender_dependent_relayhost_maps = hash:/etc/postfix/sender_relay
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options =
smtp_sasl_mechanism_filter = xoauth2

vi /etc/postfix/sender_relay
user@domain.tld [smtp.office365.com]:587

vi /etc/postfix/sasl_passwd
user@domain.tld user@domain.tld:<TOKEN>


postmap /etc/postfix/sender_relay
postmap /etc/postfix/sasl_passwd

service postfix restart
