# -*- mode: cperl; mode: follow; -*-
#

package Regather::Config;

use strict;
use warnings;
use diagnostics;
use parent 'Config::Parser::Ini';
use Carp;
use File::Basename;

sub new {
  my $class        = shift;
  local %_         = @_;
  my $nodes        = delete $_{add_nodes};
  my $fg           = delete $_{fg};
  my $logger       = delete $_{logger};
  my $filename     = delete $_{filename};
  my $verbose      = delete $_{verbose};
  my $self         = $class->SUPER::new(%_);
  $self->{logger}  = $logger;
  $self->{verbose} = $verbose;
  $self->parse($filename);
  $self->commit or return;
  while (my ($key, $val) = each %$nodes) {
    next if ! %$val;
    while (my ($k, $v) = each %$val) {
      # next if $self->is_set($key, $k);
      $self->set($key, $k, $v);
    }
  }
  $self
}

sub error {
  my $self = shift;
  my $err  = shift;
  local %_ = @_;
  my $locus = $_{locus} ? $_{locus} . ': ' : '';
  $self->{logger}->logg({ pr => 'err',
			  fm => "config parser error: %s%s",
			  ls => [ $locus, $err ] });
}

=head2 chk_dir

check wheather the target directory exists

=cut

sub chk_dir {
  my ($self, $valref, $prev_value, $locus) = @_;

  unless ( -d $$valref ) {
    $self->error("directory \"$$valref\" does not exist",
		 locus => $locus);
    return 0;
  }
  return 1;
}

sub chk_dir_pid {
  my ($self, $valref, $prev_value, $locus) = @_;
  my $dir = dirname($$valref);
  unless ( -d $dir ) {
    $self->error("pid file directory \"$dir\"does not exist",
		 locus => $locus);
    return 0;
  }
  return 1;
}

sub chk_file_tt {
  my ($self, $valref, $prev_value, $locus) = @_;
  my $tt = sprintf("%s/%s",
		   $self->tree->subtree('core')->subtree('tt_path')->value,
		   $$valref);

  unless ( -f $tt && -r $tt  ) {
    $self->error(sprintf("file \"%s\" does not exist", $tt),
		 locus => $locus);
    return 0;
  }
  return 1;
}

=head2 mangle

to add single node

=cut

sub mangle {
  my $self = shift;
  my $item;

  if ( $self->is_set(qw(core uid)) ) {
    $item = getpwnam( $self->get(qw(core uid)) );
    if ( defined $item ) {
      $self->{logger}->logg({ pr => 'info', fm => "setuid user %s(%s) confirmed",
			      ls => [ $self->get(qw(core uid)), $item ] })
	if $self->{verbose} > 1;
      $self->set('core', 'uid_number', $item);
    } else {
      print "No user $self->get('uid') found\n\n";
      exit 2;
    }
  }

  if ( $self->is_set(qw(core gid)) ) {
    $item = getgrnam( $self->get(qw(core gid)) );
    if ( defined $item ) {
      $self->{logger}->logg({ pr => 'info', fm => "setgid group %s(%s) confirmed",
			      ls => [ $self->get(qw(core gid)), $item ] })
	if $self->{verbose} > 1;
      $self->set('core', 'gid_number', $item);
    } else {
      print "No group $self->get('gid') found\n\n";
      exit 2;
    }
  }

  foreach ( $self->names_of('service') ) {
    if ( $self->is_set(qw($_ uid)) ) {
      $item = getpwnam( $self->get(qw($_ uid)) );
      if ( defined $item ) {
	$self->{logger}->logg({ pr => 'info', fm => "setuid user %s(%s) confirmed",
				ls => [ $self->get(qw($_ uid)), $item ] })
	  if $self->{verbose} > 1;
	$self->set($_, 'uid_number', $item);
      } else {
	print "No user $self->get('uid') found\n\n";
	exit 2;
      }
    }

    if ( $self->is_set(qw($_ gid)) ) {
      $item = getgrnam( $self->get(qw($_ gid)) );
      if ( defined $item ) {
	$self->{logger}->logg({ pr => 'info', fm => "setgid group %s(%s) confirmed",
				ls => [ $self->get(qw($_ gid)), $item ] })
	  if $self->{verbose} > 1;
	$self->set($_, 'gid_number', $item);
      } else {
	print "No group $self->get('gid') found\n\n";
	exit 2;
      }
    }
  }

  %{$item} = $self->get_ldap_config_file;
  while ( my ($k, $v) = each %{$item} ) {
    next if defined $self->get('ldap', $k);
    $self->set('ldap', $k, $v);
  }

}

sub get_ldap_config_file {
  my $self = shift;

  my $ldap_config = {};
  my @ldap_config_files = qw( /usr/local/etc/openldap/ldap.conf
			      /etc/ldap.conf
			      /etc/ldap/ldap.conf
			      /etc/openldap/ldap.conf );

  unshift @ldap_config_files, $ENV{LDAP_CONF} if defined($ENV{LDAP_CONF});

  my $file;
  my $line = 0;
  my %ldap_cf;

  foreach (@ldap_config_files) {
    if ( -e $_ ) {
      open($file, "<", $_) || do {
	die "cannot open $_: $!";
	exit 1;
      };
      while (<$file>) {
	++$line;
	chomp;
	s/^\s+//;
	s/\s+$//;
	s/#.*//;
	next if ($_ eq "");
	my @kvp = split(/\s+/, $_, 2);
	$ldap_cf{lc($kvp[0])} = $kvp[1];
      }
      close($file);
      last;
    }
  }
  return %ldap_cf;
}

1;

__DATA__

[core]
gid          = STRING
pid_file     = STRING :check=chk_dir_pid :default /var/run/openldap/regather.pid
tt_debug     = NUMBER :default 0
tt_path      = STRING :check=chk_dir :default /usr/local/etc/regather.d
uid          = STRING

[log]
facility     = STRING :default local4
colors       = NUMBER :default 0
foreground   = NUMBER :default 0
verbosity    = NUMBER :default 0

[ldap]
base   = STRING
debug  = NUMBER :default 0
filter = STRING :mandatory
scope  = STRING :default sub

[service ANY]
chmod        = OCTAL  :default 0640
chown	     = NUMBER :default 1
ctrl_attr    = STRING :mandatory
gid          = STRING
out_ext      = STRING
out_file     = STRING
out_file_pfx = STRING
out_path     = STRING :check=chk_dir
skip         = NUMBER :default 0
tt_file      = STRING :mandatory :check=chk_file_tt
uid          = STRING

[service ANY map s]
ANY           = STRING

[service ANY map m]
ANY           = STRING
