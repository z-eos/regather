# -*- mode: cperl; mode: follow; -*-
#

package Regather::Config;

use strict;
use warnings;
use diagnostics;
use parent 'Config::Parser::Ini';
use Carp;
use File::Basename;

use constant LDAP => { opt => { async      => '',
				debug      => '',
				inet4      => '',
				inet6      => '',
				keepalive  => '',
				localaddr  => '',
				multihomed => '',
				onerror    => '',
				port       => 'port',
				raw        => '',
				scheme     => '',
				timeout    => 'timeout',
				uri        => 'uri',
				version    => '',
			      },

		       ssl => {
			       cafile     => 'tls_cacert',
			       capath     => 'tls_cacertdir',
			       checkcrl   => 'tls_crlfile',
			       ciphers    => 'tls_cipher_suite',
			       clientcert => 'tls_cert',
			       clientkey  => 'tls_key',
			       keydecrypt => '',
			       sslversion => 'tls_protocol_min',
			       verify     => { tls_reqcert => {
							       none   => 'never',
							       allow  => 'optional',
							       demand => 'require',
							       hard   => 'require',
							       try    => 'optional',
							      },
					     },
			      },
		       bnd => {
			       anonymous => '',
			       dn        => 'binddn',
			       password  => 'bindpw',
			      },

		       srch=> {
			       attrs     => '',
			       base      => 'base',
			       filter    => '',
			       raw       => '',
			       scope     => '',
			       sizelimit => 'sizelimit',
			       timelimit => 'timelimit',
			      }
		     };

=pod

=encoding UTF-8

=head1 NAME

Regather::Config - config file processing class

=head1 SYNOPSIS

    use Regather::Config;
    my $cf = new Regather::Config ( filename  => $config,
    			            logger    => $log,
    				    cli       => $cli,
    				    verbose   => $v );

    if ( ! defined $cf ) {
      $log->logg({ pr => 'err', fm => "do fix config file ..." });
      pod2usage(-exitval => 2, -sections => [ qw(USAGE) ]);
      exit 1;
    }

    if ( $config_file_options_help_requested ) {
      $cf->config_help;
      exit 1;
    }
=head1 DESCRIPTION

This is a class to log messages.

=head1 CONSTRUCTOR

=over 4

=item new

Creates a new B<Regather::Config> object

=over 4

=item filename =E<gt> config-file-name

Name of the file to parse.

=item cli =E<gt> = delete $_{cli};

Hash with CLI provided config options.

=item logger =E<gt> = delete $_{logger};

Regather::Logg object created preliminary.

=item fg =E<gt> 0 | 1

wheather we run in foreground

=item verbose  =E<gt> N

verbosity level

=back

=back

=cut

sub new {
  my $class = shift;
  local %_  = @_;

  my $filename = delete $_{filename};
  my $cli      = delete $_{cli};
  my $logger   = delete $_{logger};
  my $fg       = delete $_{fg};
  my $verbose  = delete $_{verbose};
  my $nodes    = delete $_{add_nodes};

  my $self = $class->SUPER::new(%_);

  $self->{logger}  = $logger;
  $self->{verbose} = $verbose;

  $self->get_ldap_config_file;

  $self->parse($filename);
  $self->commit or return;

  if ( defined $cli && ref($cli) eq 'HASH' ) {
    while ( my( $k, $v ) = each %{$cli} ) {
      $self->add_value($k, $v, new Text::Locus("option \"$k\" provided from CLI",1)) ||
	exit 1;
    }
  } else {
    $self->error("malformed option/s provided from CLI");
    exit 1;
  }

  # set node/s (absent in config file) from arguments if any
  if ( defined $nodes ) {
    while (my ($key, $val) = each %$nodes) {
      next if ! %$val;
      while (my ($k, $v) = each %$val) {
	# next if $self->is_set($key, $k);
	$self->set($key, $k, $v);
      }
    }
  }
  $self
}

=head1 METHODS

=over 4

=item get_ldap_config_file

ldap.conf processing (with L<Config::Parser::ldap>) to add options
from it to config object

files searched are:

    $ENV{LDAP_CONF}
    /usr/local/etc/openldap/ldap.conf
    /etc/ldap.conf
    /etc/ldap/ldap.conf
    /etc/openldap/ldap.conf );

the first one found is used.

=cut

sub get_ldap_config_file {
  my $self = shift;

  use Config::Parser::ldap;

  my $ldap_config = {};
  my @ldap_config_files = qw( /usr/local/etc/openldap/ldap.conf
			      /etc/ldap.conf
			      /etc/ldap/ldap.conf
			      /etc/openldap/ldap.conf );

  unshift @ldap_config_files, $ENV{LDAP_CONF} if defined($ENV{LDAP_CONF});

  my ( $cf, $val );

  foreach (@ldap_config_files) {
    if ( -e $_ ) {
      $cf = new Config::Parser::ldap(filename => $_ );

      foreach my $section ( keys %{ LDAP()} ) { # $section: bnd, opt or ssl
	foreach my $item ( keys %{ LDAP->{$section} } ) { # $_: item in each of ones above
	  $self->add_value( 'ldap.' . $section . '.' . $item,

			    $section eq 'ssl' && $item eq 'verify' && $cf->is_set('tls_reqcert')
			    ?
			    LDAP->{$section}->{$item}->{tls_reqcert}->{ $cf->get('tls_reqcert') }
			    :
			    $cf->get( LDAP->{$section}->{$item} ),

			    new Text::Locus("option \"$item\" provided from ldap.conf",1))
	    if LDAP->{$section}->{$item} ne '' &&
	    $cf->is_set( LDAP->{$section}->{$item} ) &&
	    ! $self->is_set( 'ldap', $section, $item );
	}
      }
      last;
    }
  }
}

=item mangle

modify the created source tree. (resolve I<uid/gid> symbolic to number, add I<altroot>)

=cut

sub mangle {
  my $self = shift;
  my ( $section, $item, $k, $v );

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

    if ( $self->is_set($_, 'gid') ) {
      $item = getgrnam( $self->get($_, 'gid') );
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

  if ( $self->is_set(qw(core altroot)) ) {
    chdir($self->get(qw(core altroot))) || do {
      $self->{logger}->logg({ pr => 'err', fm => "unable to chdir to %s",
			      ls => [ $self->get(qw(core altroot)) ] });
      exit 1;
    };

    foreach ( $self->names_of('service') ) {
      $self->add_value('service.' . $_ . '.out_path',
		       substr($self->get('service', $_, 'out_path'), 1),
		       new Text::Locus(sprintf("in \"%s\" ", $self->get(qw(core altroot))), 1)) ||
			 exit 1;
    }
  } else {
    chdir('/');
  }
}

=item config_help

print config lexicon help

=cut

sub config_help {
  my $self = shift;
  my $lex = $self->lexicon;
  my ( $default, $re, $check );
  foreach (sort keys %$lex) {
    print "\n[$_]\n";
    while ( my($k,$v) = each %{$lex->{$_}->{section}} ) {
      print sprintf("  %- 20s :default %- 40s :re %- 25s :check %s\n",
		    $k,
		    $v->{default} ? $v->{default} : '',
		    $v->{re} ? $v->{re}           : '',
		    $v->{check} ? $v->{check}     : '');
    }
  }

  if ( $self->{verbose} > 0 ) {
    print "\n\n";
    $self->{logger}->logg({ fg => 1, pr => 'info', fm => "lexicon():%s\n%s",
			    ls => [ '-' x 70, $lex ] });
  }
}

=item chk_dir

check wheather the target directory exists

=cut

sub chk_dir {
  my ($self, $valref, $prev_value, $locus) = @_;

  unless ( -d $$valref ) {
    $self->error("directory \"$$valref\" does not exist",
		 locus => $locus);
    return 0;
  }
  $self->{chk_dir_passed} = 1;
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

=item chk_file_tt

.tt file existance checker

=cut

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

=item core_only

informer (to spawn error if I<core> section option appears in other section)

=cut

sub core_only {
  my ($self, $valref, $prev_value, $locus) = @_;
  $self->error(sprintf("wrong location for option, it can appear only in the section \"core\""),
	       locus => $locus);
  return 0;
}

=item error

error handler

=back

=cut

sub error {
  my $self = shift;
  my $err  = shift;
  local %_ = @_;
  my $locus = $_{locus} ? $_{locus} . ': ' : '';
  $self->{logger}->logg({ pr => 'err',
			  fm => "config parser error: %s%s",
			  ls => [ $locus, $err ] });
}

=head1 CONFIG FILE

An ini-style configuration file is a textual file consisting of settings grouped into one or more sections.

1. do read L<Config::Parser::Ini> documentation section B<DESCRIPTION> for general description of format used.

2. look at the output of: regather -c ./etc/regather.conf --config-help

3. look into sources ... (to be amended)
=cut


1;


__DATA__

[core]
altroot      = STRING :re="^/tmp/.*" :check=chk_dir
dryrun       = NUMBER :default 0
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
altroot      = STRING :check=core_only
dryrun       = STRING :check=core_only
pid_file     = STRING :check=core_only
tt_debug     = STRING :check=core_only
tt_path      = STRING :check=core_only

[ldap]
altroot      = STRING :check=core_only
dryrun       = STRING :check=core_only
pid_file     = STRING :check=core_only
tt_debug     = STRING :check=core_only
tt_path      = STRING :check=core_only
ANY          = STRING

[ldap srch]
attrs        = STRING
base         = STRING
filter       = STRING :mandatory
raw          = STRING
scope        = STRING :default sub
sizelimit    = NUMBER :default 0
timelimit    = NUMBER :default 0
log_base     = STRING

[ldap bnd]
anonymous    = STRING
bindpw       = STRING
dn           = STRING
password     = STRING

[ldap opt]
async        = NUMBER :default 0
debug        = NUMBER :default 0
inet4        = STRING
inet6        = STRING
keepalive    = STRING
localaddr    = STRING
multihomed   = STRING
onerror      = STRING
port         = STRING
raw          = STRING
scheme       = STRING
timeout      = STRING
uri          = STRING
version      = NUMBER :default 3

[ldap ssl]
cafile       = STRING
capath       = STRING
checkcrl     = STRING
ciphers      = STRING
clientcert   = STRING
clientkey    = STRING
keydecrypt   = STRING
ssl          = STRING
sslversion   = STRING
verify       = STRING

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
ANY          = STRING
altroot      = STRING :check=core_only
dryrun       = STRING :check=core_only
pid_file     = STRING :check=core_only
tt_debug     = STRING :check=core_only
tt_path      = STRING :check=core_only

[service ANY map m]
ANY          = STRING
altroot      = STRING :check=core_only
dryrun       = STRING :check=core_only
pid_file     = STRING :check=core_only
tt_debug     = STRING :check=core_only
tt_path      = STRING :check=core_only

