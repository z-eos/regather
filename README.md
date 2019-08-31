# regather

**regather** is a syncrepl consumer to generate ( *re gather* ) files on LDAP synrepl events.

It uses Net::LDAP(3) to do all LDAP related stuff and Template(3) to generate files. Config file is processed with Config::Parser(3) (it's format described in Regather::Config(3)

As example, regather, on LDAP event can create/re-write/delete
* OpenVPN client config file/s
* CRL file for OpenVPN or FreeRADIUS
* sieve script for mail user.
* mail domain maildir directory in IMAP4 space, on domain binding to IMAP server LDAP configuration

Copyright (c) 2019 [Zeus Panchenko](https://github.com/z-eos)
