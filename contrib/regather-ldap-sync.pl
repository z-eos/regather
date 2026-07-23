#!/usr/bin/env perl
# -*- mode: cperl; eval: (follow-mode) -*-
#

use strict;
use warnings;
use diagnostics;

use File::Basename;
use Data::Printer;
use Try::Tiny;
use Getopt::Long qw(:config no_ignore_case gnu_getopt auto_version);
use Pod::Usage   qw(pod2usage);

use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Util qw(canonical_dn escape_filter_value);
use Net::LDAP::Constant
  qw( LDAP_COMPARE_FALSE
      LDAP_COMPARE_TRUE
      LDAP_INSUFFICIENT_ACCESS
      LDAP_INVALID_DN_SYNTAX
      LDAP_NO_SUCH_ATTRIBUTE
      LDAP_NO_SUCH_OBJECT
      LDAP_PROTOCOL_ERROR
      LDAP_SUCCESS
      LDAP_SYNC_ADD
      LDAP_SYNC_DELETE
      LDAP_SYNC_MODIFY
   );

our $VERSION = '0.3.2';

my %_opt =
  (
   host     => '',
   user     => '',
   password => '',
   ca       => '',
   testmode => 0,
   debug    => 3,
   defaultproj => 'infra',
   env      => {},
   progname => fileparse($0),
  );

GetOptions(
	   'H|host=s'            => \$_opt{host},
	   'ca=s'                => \$_opt{ca},
	   'u|user=s'            => \$_opt{user},
	   'p|password=s'        => \$_opt{password},
	   'P|default-project=s' => \$_opt{defaultproj},
	   'e|env=s%'            => \$_opt{env},
	   't|test-mode'         => \$_opt{testmode},
	   'd|debug+'            => \$_opt{debug},
	   'h'                   => sub { pod2usage(-exitval => 0,
						    -verbose => 2);
					  exit 0 },
	  ) or pod2usage(-exitval => 1, -verbose => 1);

logg (0, "[DEBUG LEVEL: " . $_opt{debug} . "] ");

my @mandatory_opt =
  qw(
      ca
      host
      user
      password
   );

mandatory_checks ( \@mandatory_opt, \%_opt, 'option(s)' );

@ENV{keys %{$_opt{env}}} = values %{$_opt{env}}
  if exists $_opt{env} && ref($_opt{env}) eq 'HASH';

my @mandatory_env =
  qw(
      REGATHER_LDAP_SYNC_CONTROL_NAME
      REGATHER_LDAP_OBJ_ATTR_grayHostName
      REGATHER_LDAP_OBJ_ATTR_cn
      REGATHER_LDAP_OBJ_ATTR_grayAssociatedProject
   );

mandatory_checks ( \@mandatory_env, \%ENV, 'environment variable(s)' );

$ENV{REGATHER_LDAP_SYNC_CONTROL_CODE} =
  const_val_from_name($ENV{REGATHER_LDAP_SYNC_CONTROL_NAME})
  if !exists $ENV{REGATHER_LDAP_SYNC_CONTROL_NAME};

my $proj = $_opt{testmode}
	 ? 'TEST'
	 : ( $ENV{REGATHER_LDAP_OBJ_ATTR_grayAssociatedProject} // $_opt{defaultproj} );

my $m;
my $ldap = Net::LDAP->new( $_opt{host}, async => 1, debug => 0 )
  || do { print "\n$@\n"; exit 1; };

try {
  $m = $ldap->
    start_tls(verify     => 'require',
	      cafile     => $_opt{ca},
	      checkcrl   => 0,
	      sslversion => 'sslv23',);
  logg (3, 'ERROR: Net::LDAP start_tls: ' . $m->error)
    if $m->is_error;
} catch {
  logg (3, "ERROR: Net::LDAP start_tls caught message: $_");
};

$m = $ldap->bind($_opt{user}, password => $_opt{password}, version => 3);
if ( $m->is_error ) {
  logg (3, sprintf("ldap bind code: %s; mesg: %s; txt: %s",
		   $m->code, $m->error_name, $m->error_text));
  exit 1;
}

my $dn = proj_dn($proj);
my $srch_proj = $ldap->
  search( base => $dn, scope => 'base',
	  filter => '(objectClass=*)', attrs => ['1.1'] );

if ( $srch_proj->code == LDAP_SUCCESS ) {
  ###########################################################
  #        target ou=PROJECT exists, we can proceed         #
  ###########################################################

  $dn = sprintf("ou=hosts,%s", $dn);
  my $srch_hosts =
    $ldap->search(base => $dn, scope => 'base', filter => '(objectClass=*)');

  if ( $srch_hosts->code == LDAP_SUCCESS ) {
    # ou=HOSTS exists, we proceed

    my $cmp = $ldap->
      compare( $dn, attr  => 'host',
	       value => $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName} );

    if (
	( $cmp->code == LDAP_COMPARE_FALSE
	  || $cmp->code == LDAP_NO_SUCH_ATTRIBUTE )
	&& ( $ENV{REGATHER_LDAP_SYNC_CONTROL_CODE} == LDAP_SYNC_ADD
	     || $ENV{REGATHER_LDAP_SYNC_CONTROL_CODE} == LDAP_SYNC_MODIFY )
       ) {
      ####################################################
      # ADD grayHostName TO ATTRIBUTE host VALUES        #
      ####################################################
      logg (5,
	    sprintf("no `host' attr or value `%s', add it",
		    $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName}));

      add_host($ldap, $dn, $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName});

    } elsif (
	     $cmp->code == LDAP_COMPARE_TRUE
	     && $ENV{REGATHER_LDAP_SYNC_CONTROL_CODE} == LDAP_SYNC_DELETE
	    ) {
      ####################################################
      # DELETE grayHostName TO ATTRIBUTE host VALUES     #
      ####################################################
      logg (5,
	    sprintf("%s has %s, delete it",
		    $dn, $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName}));

      del_host($ldap, $dn, $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName});

    } elsif ( $cmp->code == LDAP_COMPARE_TRUE ) {
      ##########################################################
      # DO NOTHING: ATTRIBUTE host CONTAINS grayHostName VALUE #
      ##########################################################

      logg (5, sprintf("%s has %s, do nothing", $dn,
		       $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName}));

    } else {
      logg (7, sprintf("ldap->compare returned: %s",
		       np($cmp->code)));
    }

  } elsif ( $srch_hosts->code == LDAP_NO_SUCH_OBJECT ) {
    #################################################################
    # ou=HOSTS doesn't exist, create it with attr host=grayHostName #
    #################################################################
    logg (5,
	  sprintf("there is no %s, add with host=%s",
		  $dn, $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName}));

    create_hosts($ldap, $proj);
  } else {
    logg (3, sprintf("\nERROR:\n%s\n\n", $srch_hosts->error))
      if $srch_hosts->is_error;
  }

} elsif ( $srch_proj->code == LDAP_NO_SUCH_OBJECT ) {
  ##########################################################
  #    ou=MACHINES has attr grayAssociatedProject but      #
  #    there is no target ou=PROJECT yet, so, create it    #
  ##########################################################
  logg (6, "\nproject `$proj' doesn't exist, so we need create it first\n\n");

  create_proj($ldap, $proj);
  create_hosts($ldap, $proj);
}

logg (7, sprintf("\n%s\n\n%s", '- * 'x20, np(%ENV)));

###########################################################

# PRIORITIES:
# LOG_EMERG   0 system is unusable
# LOG_ALERT   1 action must be taken immediately
# LOG_CRIT    2 critical conditions
# LOG_ERR     3 error conditions
# LOG_WARNING 4 warning conditions
# LOG_NOTICE  5 normal but significant condition
# LOG_INFO    6 informational
# LOG_DEBUG   7 debug-level messages
sub logg {
  my ($priority, $msg) = @_;
  print "$msg" if $priority <= $_opt{debug};
}

sub mandatory_checks {
  my ($mandatory, $checked, $label) = @_;

  my @miss =
  grep {
    ! defined $checked->{$_}
      || ! length $checked->{$_}
    } @$mandatory;

  if (@miss) {
    logg (3, "\nERROR: mandatory $label missing: $_\n") for @miss;
    exit 1;
  }
}

sub const_val_from_name {
  my $const_name = shift;
  if (my $constant_sub = Net::LDAP::Constant->can($const_name)) {
    my $value = $constant_sub->();
    logg (7, "The value of $const_name is: $value\n");
    return $value;
  } else {
    logg (3, "ERROR: '$const_name' is not a valid constant.\n");
  }
}

sub proj_dn {
  return
    canonical_dn([{ cn => shift }, { ou => 'Project' },
		  { dc => 'nxc' }, { dc => 'no' },]);
}

sub create_proj {
  my ($ldap, $proj ) = @_;
  my $proj_dn = proj_dn($proj);
  my $proj_args = [
		   objectClass => [ 'organizationalRole' ],
		   description => 'project ' . $proj,
		   cn => $proj,
		  ];
  my $result = $ldap->add ( $proj_dn, attrs => [ @$proj_args ] );
  logg (3, np($result->error)) if $result->is_error;
}

sub create_hosts {
  my ($ldap, $proj ) = @_;
  my $hosts_dn = 'ou=hosts,' . proj_dn($proj);
  my $hosts_args =
    [
     objectClass => [ 'top', 'organizationalUnit', 'hostObject' ],
     description => $proj . ' related hosts/servers/devicees',
     host => $ENV{REGATHER_LDAP_OBJ_ATTR_grayHostName},
     ou => 'hosts',
    ];
  my $result = $ldap->add ( $hosts_dn, attrs => [ @$hosts_args ] );
  logg (3, np($result->error)) if $result->is_error;
}

sub add_host {
  my ($ldap, $dn, $host) = @_;
  my $result = $ldap->modify( $dn, add => { host => $host } );
  logg (3, np($result->error)) if $result->is_error;
}

sub del_host {
  my ($ldap, $dn, $host) = @_;
  my $result = $ldap->modify( $dn, delete => { host => $host } );
  logg (3, np($result->error)) if $result->is_error;
}

__END__

=head1 NAME

regather-ldap-sync - reconcile a host's LDAP project/host-list membership

=head1 SYNOPSIS

  regather-ldap-sync.pl -H HOST -u BIND_DN -p PASSWORD [OPTIONS]

=head1 DESCRIPTION

Initially designed to run under regather(8) plugin I<script>, besides
that can work as standalone script.

Invoked per host by the calling sync process (or manually, using
B<-e>). Reads host's project association and the sync operation to
perform from the C<REGATHER_LDAP_OBJ_ATTR_*> /
C<REGATHER_LDAP_SYNC_CONTROL_*> environment variables, then adds or
removes that host from the C<host> attribute of the corresponding
project's C<ou=hosts> object in LDAP - creating the project and/or its
C<ou=hosts> object first if they don't yet exist.

All output goes to STDOUT, gated by verbosity level.

=head1 OPTIONS

=over 4

=item B<-H>, B<--host> I<STRING>

LDAP server hostname. Required.

=item B<-u>, B<--user> I<STRING>

Bind DN. Required.

=item B<-p>, B<--password> I<STRING>

Bind password. Required.

=item B<-P>, B<--default-project> I<STRING>

Project to use when C<REGATHER_LDAP_OBJ_ATTR_grayAssociatedProject> is
unset. Default: C<infra>.

=item B<-e>, B<--env> I<KEY=VALUE>

Set or override an environment variable for this run. Repeatable. Lets
you invoke the script standalone (e.g. for testing) without relying on
the calling process to export C<REGATHER_*> variables.

=item B<-t>, B<--test-mode>

Force the target project to C<TEST>, regardless of
C<REGATHER_LDAP_OBJ_ATTR_grayAssociatedProject> or B<-P>. Use to
validate the script against a disposable project without risking any
other project's data.

=item B<-d>, B<--debug>

Raise log verbosity by one per occurrence (stackable: C<-d>, C<-dd>,
C<-ddd>, C<-dddd>). C<LOG_ERR> and more severe are shown by default
with no B<-d> at all. See L</"LOGGING VERBOSITY"> for the full scale.

=item B<-h>

Show this help and exit.

=back

=head1 ENVIRONMENT VARIABLES

Normally exported by the calling sync process; use B<-e> to set them
manually for standalone/manual runs.

=over 4

=item C<REGATHER_LDAP_SYNC_CONTROL_NAME>

Human-readable sync action name. Used for logging only. Required.

=item C<REGATHER_LDAP_SYNC_CONTROL_CODE>

Sync action code: C<1>=ADD, C<2>=DELETE, C<3>=MODIFY (matches
C<Net::LDAP::Constant>'s C<LDAP_SYNC_*> values). Required.

=item C<REGATHER_LDAP_OBJ_ATTR_grayHostName>

Hostname to add/remove. Required.

=item C<REGATHER_LDAP_OBJ_ATTR_cn>

Object cn, used for log messages. Required.

=item C<REGATHER_LDAP_OBJ_ATTR_grayAssociatedProject>

Project the host belongs to. Optional - falls back to
B<--default-project> if unset.

=back

=head1 LOGGING VERBOSITY

Each message is logged at a syslog-style priority; B<-d> raises the
threshold of what gets printed by one level per occurrence, starting
from C<LOG_ERR> shown by default with no B<-d> at all:

=over 4

=item 0 - LOG_EMERG   - system is unusable

=item 1 - LOG_ALERT   - action must be taken immediately

=item 2 - LOG_CRIT    - critical conditions

=item 3 - LOG_ERR     - error conditions (shown by default)

=item 4 - LOG_WARNING - warning conditions

=item 5 - LOG_NOTICE  - normal but significant condition

=item 6 - LOG_INFO    - informational

=item 7 - LOG_DEBUG   - debug-level messages

=back

=head1 EXAMPLE

    regather-ldap-sync.pl -t -d \
	-e REGATHER_LDAP_SYNC_CONTROL_NAME=LDAP_SYNC_ADD \
	-e REGATHER_LDAP_SYNC_CONTROL_CODE=1 \
	-e REGATHER_LDAP_OBJ_ATTR_grayHostName=TEST123.foo.bar \
	-e REGATHER_LDAP_OBJ_ATTR_cn=foo.bar \
	-e REGATHER_LDAP_OBJ_ATTR_grayAssociatedProject=TEST \
	-H ldap.foo.bar \
	-u uid=***,ou=People,dc=foo,dc=bar \
	-p ***

=head1 EXIT STATUS

=over 4

=item 0 Completed (includes "no action needed" outcomes).

=item 1 Bind/connection failure, or a mandatory option/environment variable is
missing.

=back

=head1 AUTHOR

Zeus Panchenko E<lt>zeus@gnu.org.uaE<gt>

=cut
