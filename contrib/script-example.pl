#!/usr/bin/env perl
# -*- mode: cperl; eval: (follow-mode) -*-
#

use strict;
use warnings;
use diagnostics;

use Data::Printer;

my $ou = sprintf("/tmp/regather-plugin-script-perl-%s.txt",
		 $ENV{"REGATHER_LDAP_OBJ_ATTR_uid"});

open(my $fh, ">", $ou) || do {
  print "Can't open > $ou for writing: $!";
  exit 1;
};

print $fh np(%ENV);

close($fh) || do {
  print "close $ou (opened for writing), failed: $!\n\n";
  exit 1;
};

