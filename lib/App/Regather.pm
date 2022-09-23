# -*- mode: cperl; eval: (follow-mode); -*-
#

package App::Regather;

use strict;
use warnings;
use diagnostics;

use Carp;
use File::Basename;
use Getopt::Long qw(:config no_ignore_case gnu_getopt auto_version);
use IPC::Open2;
use List::Util   qw(uniqstr);
use List::MoreUtils qw(any onlyval);

use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Constant qw( 
			    LDAP_CONNECT_ERROR
			    LDAP_LOCAL_ERROR
			    LDAP_OPERATIONS_ERROR
			    LDAP_SUCCESS
			    LDAP_SYNC_ADD
			    LDAP_SYNC_DELETE
			    LDAP_SYNC_MODIFY
			    LDAP_SYNC_PRESENT
			    LDAP_SYNC_REFRESH_AND_PERSIST
			    LDAP_SYNC_REFRESH_ONLY
			 );
use Net::LDAP::Control::SyncRequest;
use Net::LDAP::Util qw(generalizedTime_to_time);

use POSIX;
use Pod::Usage   qw(pod2usage);
use Sys::Syslog  qw(:standard :macros);
use Template;

use App::Regather::Config;
use App::Regather::Logg;
use App::Regather::Plugin;

use constant SYNST => [ qw( LDAP_SYNC_PRESENT LDAP_SYNC_ADD LDAP_SYNC_MODIFY LDAP_SYNC_DELETE ) ];

# my @DAEMONARGS = ($0, @ARGV);
our $VERSION   = '0.90.00';

=head2 new

method `new` - constructor

=cut

sub new {
  my $class = shift;
  my $self =
    bless {
	   _progname => fileparse($0),
	   _daemonargs => [$0, @ARGV],
	   _opt   => {
		      ch          => undef,
		      cli         => undef,
		      colors      => 0,
		      config      => '/usr/local/etc/regather.conf',
		      fg          => 0,
		      force       => 0,
		      plugin_list => 0,
		      strict      => 0,
		      ts_fmt      => "%a %F %T %Z (%z)",
		      v           => 0,
		     }
	  }, $class;

  GetOptions(
	     'f|foreground' => \$self->{_opt}{fg},
	     'F|force'      => \$self->{_opt}{force},
	     'c|config=s'   => \$self->{_opt}{config},
	     'colors'       => \$self->{_opt}{colors},
	     'C|cli=s%'     => \$self->{_opt}{cli},
	     'S|strict'     => \$self->{_opt}{strict},
	     'config-help'  => \$self->{_opt}{ch},
	     'plugin-list'  => \$self->{_opt}{plugin_list},
	     'v+'           => \$self->{_opt}{v},
	     'h'            => sub { pod2usage(-exitval => 0, -verbose => 2); exit 0 },
	    );

  $self->{_opt}{l} = new
    App::Regather::Logg( prognam    => $self->{_progname},
			 foreground => $self->{_opt}{fg},
			 colors     => $self->{_opt}{colors} );

  if ( $self->{_opt}{plugin_list} ) {
    App::Regather::Plugin->new( 'list' )->run;
    exit 0;
  }

  if ( ! -e $self->{_opt}{config} || -z $self->{_opt}{config} ) {
    $self->{_opt}{l}->cc(          pr => 'err', fm => "config file does not exist or is empty" );
    $self->{_opt}{l}->cc( fg => 1, pr => 'err', fm => "config file does not exist or is empty" );
    pod2usage(-exitval => 2, -sections => [ qw(USAGE) ]);
    exit 1;
  }

  $self->{_opt}{cf} = new
    App::Regather::Config ( filename => $self->{_opt}{config},
			    logger   => $self->{_opt}{l},
			    cli      => $self->{_opt}{cli},
			    verbose  => $self->{_opt}{v} );

  my $cf_mode = (stat($self->{_opt}{config}))[2] & 0777;
  my $fm_msg;
  if ( $cf_mode & 002 || $cf_mode & 006 ) {
    $fm_msg = 'world';
  } elsif ( $cf_mode & 020 || $cf_mode & 060) {
    $fm_msg = 'group';
  }
  if ( defined $fm_msg ) {
    $self->{_opt}{l}->cc(          pr => 'err', fm => 'config file is accessible by ' . $fm_msg);
    $self->{_opt}{l}->cc( fg => 1, pr => 'err', fm => 'config file is accessible by ' . $fm_msg);
    pod2usage(-exitval => 2, -sections => [ qw(USAGE) ]);
    exit 1;
  }

  $self->{_opt}{last_forever} = 1;

  # !!! TO CORRECT
  if ( ! defined $self->{_opt}{cf} ) {
    $self->l->cc(          pr => 'err', fm => "do fix config file ..." );
    $self->l->cc( fg => 1, pr => 'err', fm => "do fix config file ..." );
    pod2usage(-exitval => 2, -sections => [ qw(USAGE) ]);
    exit 1;
  }

  if ( $self->{_opt}{ch} ) {
    $self->{_opt}{cf}->config_help;
    exit 1;
  }

  return $self;
}

sub progname { shift->{_progname} }

sub progargs { return join(' ', @{shift->{_daemonargs}}); }

sub cf { shift->{_opt}{cf} }

sub l { shift->{_opt}{l} }

sub o {
  my ($self,$opt) = @_;
  croak "unknown/undefined variable"
    if ! exists $self->{_opt}{$opt};
  return $self->{_opt}{$opt};
}

=head2 run()

method `run`

=cut

sub run {
  my $self = shift;

  $self->l->cc( pr => 'info', fm => "%s:%s: options provided from CLI:\n%s", ls => [ __FILE__,__LINE__, $self->o('cli') ] )
    if defined $self->o('cli') && keys( %{$self->o('cli')} ) && $self->o('v') > 1;

  $self->l->set_m( $self->cf->getnode('log')->as_hash );
  $self->l->set( notify       => [ $self->cf->get('core', 'notify') ] );
  $self->l->set( notify_email => [ $self->cf->get('core', 'notify_email') ] );

  $self->l->cc( pr => 'info', fm => "%s: Dry Run is set on, no file is to be changed\n" )
    if $self->cf->get(qw(core dryrun));
  $self->l->cc( pr => 'info', fm => "%s:%s: Config::Parse object as hash:\n%s",
	        ls => [ __FILE__,__LINE__, $self->cf->as_hash ] ) if $self->o('v') > 3;
  $self->l->cc( pr => 'info', fm => "%s:%s: %s",
		ls => [ __FILE__,__LINE__, $self->progargs ] );
  $self->l->cc( pr => 'info', fm => "%s:%s: %s v.%s is starting ...",
		ls => [ __FILE__,__LINE__, $self->progname, $VERSION, ] );

  @{$self->{_opt}{svc}} = grep { $self->cf->get('service', $_, 'skip') != 1 } $self->cf->names_of('service');

  $self->daemonize if ! $self->o('fg');

  our $s;
  my  $tmp;
  my  $cfgattrs = [];
  my  $mesg;
  my  @svc_map;

  foreach my $i ( @{$self->{_opt}{svc}} ) {
    foreach ( qw( s m ) ) {
      if ( $self->cf->is_section('service', $i, 'map', $_) ) {
	@svc_map = values( %{ $self->cf->getnode('service', $i, 'map', $_)->as_hash } );
	# push @svc_map, $self->cf->getnode('service', $i, 'ctrl_attr');
	$cfgattrs = [ @{$cfgattrs}, @svc_map, @{$self->cf->get('service', $i, 'ctrl_attr')} ];
      } else {
	@svc_map = ();
      }
    }

    push @{$cfgattrs}, '*'
      if $self->cf->get('service', $i, 'all_attr') != 0;

    $self->l->cc( pr => 'warning', ls => [ __FILE__,__LINE__, $i, ],
		  fm => "%s:%s: no LDAP attribute to process is mapped for service `%s`" )
      if $self->cf->get('service', $i, 'all_attr') == 0 && scalar @svc_map == 0;

  }

  @{$tmp} = sort @{[ @{$cfgattrs}, qw( associatedDomain
				       authorizedService
				       description
				       entryUUID
				       entryCSN
				       createTimestamp
				       creatorsName
				       modifiersName
				       modifyTimestamp ) ]};
  @{$cfgattrs} = uniqstr @{$tmp};

  #
  ## -=== MAIN LOOP =====================================================-
  #

  my $ldap_opt      = $self->cf->getnode(qw(ldap opt))->as_hash;
  my $uri           = delete $ldap_opt->{uri};
  while ( $self->o('last_forever') ) {
    if ( $self->cf->is_set(qw(core altroot)) ) {
      chdir($self->cf->get(qw(core altroot))) || do {
	$self->l->cc( pr => 'err', fm => "%s:%s: main: unable to chdir to %s",
		      ls => [ __FILE__,__LINE__, $self->cf->get(qw(core altroot)) ] );
	exit 1;
      };
    }

    $self->{_opt}{ldap} =
      Net::LDAP->new( $uri, @{[ map { $_ => $ldap_opt->{$_} } %$ldap_opt ]} )
	|| do {
	  $self->l->cc( pr => 'err', fm => "%s:%s: Unable to connect to %s; error: %s",
			ls => [ __FILE__,__LINE__, $uri, $! ] );
	  if ( $self->o('strict') ) {
	    exit LDAP_CONNECT_ERROR;
	  } else {
	    next;
	  }
	};

    my $start_tls_options = $self->cf->getnode(qw(ldap ssl))->as_hash if $self->cf->is_section(qw(ldap ssl));
    if ( exists $start_tls_options->{ssl} && $start_tls_options->{ssl} eq 'start_tls' ) {
      delete $start_tls_options->{ssl};
      eval {
	$mesg =
	  $self->o('ldap')->start_tls( @{[ map { $_ => $start_tls_options->{$_} } %$start_tls_options ]} );
      };
      if ( $@ ) {
	$self->l->cc( pr => 'err', fm => "%s:%s: TLS negotiation failed: %s", ls => [ __FILE__,__LINE__, $! ] );
	if ( $self->o('strict') ) {
	  exit LDAP_CONNECT_ERROR;
	} else {
	  next;
	}
      } else {
	$self->l->cc( pr => 'info', fm => "%s: TLS negotiation succeeded" ) if $self->o('v') > 1;
      }
    }

    my $bind = $self->cf->getnode(qw(ldap bnd))->as_hash if $self->cf->is_section(qw(ldap bnd));
    if ( ref($bind) eq 'HASH' ) {
      if ( exists $bind->{dn} ) {
	my @bind_options;
	push @bind_options, delete $bind->{dn};
	while ( my($k, $v) = each %{$bind} ) {
	  push @bind_options, $k => $v;
	}
	$mesg = $self->o('ldap')->bind( @bind_options );
	if ( $mesg->code ) {
	  ####### !!!!!!! TODO: to implement exponential delay on error sending to awoid log file/notify
	  ####### !!!!!!! queue overflow
	  $self->l->cc( pr => 'err', fm => "%s:%s: bind error: %s",
			ls => [ __FILE__,__LINE__, $mesg->error ] );
	  if ( $self->o('strict') ) {
	    exit $mesg->code;
	  } else {
	    next;
	  }
	}
      }
    }

    $self->{_opt}{req} =
      Net::LDAP::Control::SyncRequest->new( mode     => LDAP_SYNC_REFRESH_AND_PERSIST,
					    critical => 1,
					    cookie   => undef, );

    $mesg = $self->o('ldap')->search( base      => $self->cf->get(qw(ldap srch base)),
				      scope     => $self->cf->get(qw(ldap srch scope)),
				      control   => [ $self->o('req') ],
				      callback  => sub {$self->ldap_search_callback(@_)},
				      filter    => $self->cf->get(qw(ldap srch filter)),
				      attrs     => $cfgattrs,
				      sizelimit => $self->cf->get(qw(ldap srch sizelimit)),
				      timelimit => $self->cf->get(qw(ldap srch timelimit)),
				    );
    if ( $mesg->code ) {
      $self->l->cc( pr => 'err',
		    fm => "%s:%s: LDAP search ERROR...\n% 13s%s\n% 13s%s\n% 13s%s\n% 13s%s\n\n",
		    ls => [ __FILE__,__LINE__,
			    'base: ',   $self->cf->get(qw(ldap srch base)),
			    'scope: ',  $self->cf->get(qw(ldap srch scope)),
			    'filter: ', $self->cf->get(qw(ldap srch filter)),
			    'attrs: ',  join("\n", @{$cfgattrs}) ] );
      $self->l->cc_ldap_err( mesg => $mesg );
      exit $mesg->code if $self->o('strict');
    } else {
      $self->l->cc( pr => 'info',
		    fm => "%s:%s: LDAP search:\n% 13s%s\n% 13s%s\n% 13s%s\n% 13s%s\n\n",
		    ls => [ __FILE__,__LINE__,
			    'base: ',   $self->cf->get(qw(ldap srch base)),
			    'scope: ',  $self->cf->get(qw(ldap srch scope)),
			    'filter: ', $self->cf->get(qw(ldap srch filter)),
			    'attrs: ',  join("\n", @{$cfgattrs}) ] ) if $self->o('v') > 2;
    }
  }

  $mesg = $self->o('ldap')->unbind;
  if ( $mesg->code ) {
    $self->l->cc_ldap_err( mesg => $mesg );
    exit $mesg->code;
  }

  closelog();

}

#
## ===================================================================
#

=head2 daemonize()

method `daemonize`

=cut

sub daemonize {
  my $self = shift;

  my ( $pid, $fh, $pp, $orphaned_pid_mtime );
  if ( -e $self->cf->get(qw(core pid_file)) ) {
    open( $fh, "<", $self->cf->get(qw(core pid_file))) || do {
      die "Can't open $self->cf->get(qw(core pid_file)) for reading: $!";
      exit 1;
    };
    $pid = <$fh>;
    close($fh) || do {
      print "close $self->cf->get(qw(core pid_file)) (opened for reading) failed: $!\n\n";
      exit 1;
    };

    if ( kill(0, $pid) ) {
      print "Doing nothing\npidfile $self->cf->get(qw(core pid_file)) of the proces with pid $pid, exists and the very process is alive\n\n";
      exit 1;
    }

    $orphaned_pid_mtime = strftime( $self->o('ts_fmt'), localtime( (stat( $self->cf->get(qw(core pid_file)) ))[9] ));
    if ( unlink $self->cf->get(qw(core pid_file)) ) {
      $self->l->cc( pr => 'debug', fm => "%s:%s: orphaned %s was removed",
		    ls => [ __FILE__,__LINE__, $self->cf->get(qw(core pid_file)) ] )
	if $self->o('v') > 0;
    } else {
      $self->l->cc( pr => 'err', fm => "%s:%s: orphaned %s (mtime: %s) was not removed: %s",
		    ls => [ __FILE__,__LINE__, $self->cf->get(qw(core pid_file)), $orphaned_pid_mtime, $! ] );
      exit 2;
    }

    undef $pid;
  }

  $pid = fork();
  die "fork went wrong: $!\n\n" unless defined $pid;
  exit(0) if $pid != 0;

  setsid || do { print "setsid went wrong: $!\n\n"; exit 1; };

  open( $pp, ">", $self->cf->get(qw(core pid_file))) || do {
    print "Can't open $self->cf->get(qw(core pid_file)) for writing: $!"; exit 1; };
  print $pp "$$";
  close( $pp ) ||
    do {
      print "close $self->cf->get(qw(core pid_file)) (opened for writing), failed: $!\n\n";
      exit 1; };

  if ( $self->o('v') > 1 ) {
    open (STDIN,  "</dev/null") ||
      do { print "Can't redirect /dev/null to STDIN\n\n";  exit 1; };
    open (STDOUT, ">/dev/null") ||
      do { print "Can't redirect STDOUT to /dev/null\n\n"; exit 1; };
    open (STDERR, ">&STDOUT")   ||
      do { print "Can't redirect STDERR to STDOUT\n\n";    exit 1; };
  }

  $SIG{HUP}  =
    sub { my $sig = @_;
	  $self->l->cc( pr => 'warning', fm => "%s:%s: SIG %s received, restarting", ls => [ __FILE__,__LINE__, $sig ] );
	  exec('perl', @{$self->o('_daemonargs')}); };
  $SIG{INT} = $SIG{QUIT} = $SIG{ABRT} = $SIG{TERM} =
    sub { my $sig = @_;
	  $self->l->cc( pr => 'warning', fm => "%s:%s:  SIG %s received, exiting", ls => [ __FILE__,__LINE__, $sig ] );
	  $self->{_opt}{last_forever} = 0;
	};
  $SIG{PIPE} = 'ignore';
  $SIG{USR1} =
    sub { my $sig = @_;
	  $self->l->cc( pr => 'warning', fm => "%s:%s: SIG %s received, doing nothing" ), ls => [ __FILE__,__LINE__, $sig ] };

  if ( $self->cf->is_set(qw(core uid)) && $self->cf->is_set(qw(core gid)) ) {
    setgid ( $self->cf->get(qw(core gid_number)) ) || do { print "setgid went wrong: $!\n\n"; exit 1; };
    setuid ( $self->cf->get(qw(core uid_number)) ) || do { print "setuid went wrong: $!\n\n"; exit 1; };
  }

  $self->l->cc( pr => 'info', fm => "%s:%s: %s v.%s is started.", ls => [ __FILE__,__LINE__, $self->progname, $VERSION ] );
}



=head2 ldap_search_callback

method `ldap_search_callback`

=cut

sub ldap_search_callback {
  my ( $self, $msg, $obj ) = @_;

  my @controls = $msg->control;
  my $syncstate = scalar @controls ? $controls[0] : undef;

  my ( $s, $st, $mesg, $entry, @entries, $ldif, $map, $filter,
       $entryUUID, $obj_full, $reqType,
       $out_file_pfx_old, $tmp_debug_msg, $rdn, $rdn_old, $rdn_re,
       $pp, $chin, $chou, $chst, $cher, $email, $email_body );

  if ( defined $obj && $obj->isa('Net::LDAP::Entry') ) {
    $rdn = ( split(/=/, ( split(/,/, $obj->dn) )[0]) )[0];
    if ( defined $syncstate && $syncstate->isa('Net::LDAP::Control::SyncState') ) {
      $self->l->cc( pr => 'debug', fm => "%s:%s: SYNCSTATE:\n%s:",
		    ls => [ __FILE__,__LINE__, $syncstate ] )
	if $self->o('v') > 5;
      $st = $syncstate->state;
      my %reqmod;
      $self->l->cc( fm => "%s:%s: received control %s: dn: %s",
		    ls => [ __FILE__,__LINE__, SYNST->[$st], $obj->dn ] );

      $self->l->cc( pr => 'debug', fm => "%s:%s: %s: plugins to run: %s",
		    ls => [ __FILE__,__LINE__, SYNST->[$st],
			    $self->{_opt}{svc} ] )
	if $self->o('v') > 5;

      ############################################################
      ####### --- PRELIMINARY STUFF ------------------>>>>>>>>> 0
      ############################################################

      $self->l->cc( pr => 'debug', fm => "%s:%s: msg: %s",
		    ls => [ __FILE__,__LINE__, $msg ] )
	if $self->o('v') > 5;
      $self->l->cc( pr => 'debug', fm => "%s:%s: syncstate: %s",
		    ls => [ __FILE__,__LINE__, $syncstate ] )
	if $self->o('v') > 5;
      $self->l->cc( pr => 'debug', fm => "%s:%s: object: %s",
		    ls => [ __FILE__,__LINE__, $obj->ldif ] )
	if $self->o('v') > 5;

      if ( $st == LDAP_SYNC_DELETE ) { ###------------------------


	### !!! acclog object comes *after* the event
	sleep 2;
	$filter = '(&(reqType=delete)(reqDN=' . $obj->dn . '))';
	$mesg = $self->o('ldap')->
	  search( base => $self->cf->get(qw(ldap srch log_base)),
		  scope     => 'sub',
		  sizelimit => $self->cf->get(qw(ldap srch sizelimit)),
		  timelimit => $self->cf->get(qw(ldap srch timelimit)),
		  filter    => $filter, );
	if ( $mesg->code ) {
	  $self->l->cc( pr => 'err', nt => 1,
			fm => "%s:%s: LDAP accesslog search on %s, error:\n% 13s%s\n% 13s%s\n% 13s%s\n\n",
			ls => [ __FILE__,__LINE__, SYNST->[$st],
				'base: ',   $self->cf->get(qw(ldap srch log_base)),
				'scope: ',  'sub',
				'filter: ', $filter ] );
	  $self->l->cc_ldap_err( mesg => $mesg );
	  # exit $mesg->code; # !!! NEED TO DECIDE WHAT TO DO
	} else {
	  if ( $mesg->count == 0 ) {
	    $self->l->cc( pr => 'err', nt => 1,
			  fm => "%s:%s: LDAP accesslog search on %s, returned no result:\n% 13s%s\n% 13s%s\n% 13s%s",
			  ls => [ __FILE__,__LINE__, SYNST->[$st],
				  'base: ',   $self->cf->get(qw(ldap srch log_base)),
				  'scope: ',  'sub',
				  'filter: ', $filter ] );
	    return;
	  } else {
	    ### here we pop out the latest log record
	    $entry = pop @{[$mesg->sorted]};

	    $self->l->cc( pr => 'debug',
			  fm => "%s:%s: LDAP accesslog entry on %s is:\n%s\n% 13s%s\n% 13s%s\n% 13s%s",
			  ls => [ __FILE__,__LINE__, SYNST->[$st], $entry->ldif,
				  'base: ',   $self->cf->get(qw(ldap srch log_base)),
				  'scope: ',  'sub',
				  'filter: ', $filter ] )
	      if $self->o('v') > 5;
	  }
	}


      } elsif ( $st == LDAP_SYNC_MODIFY ) { ###-------------------

	### !!! acclog object comes *after* the event
	sleep 2;
	$filter = '(reqEntryUUID=' . $obj->get_value('entryUUID') . ')';
	$mesg = $self->o('ldap')->
	  search( base      => $self->cf->get(qw(ldap srch log_base)),
		  scope     => 'sub',
		  sizelimit => $self->cf->get(qw(ldap srch sizelimit)),
		  timelimit => $self->cf->get(qw(ldap srch timelimit)),
		  filter    => $filter, );
	if ( $mesg->code ) {
	  $self->l->cc( pr => 'err', nt => 1,
			fm => "%s:%s: LDAP accesslog search on %s, error:\n% 13s%s\n% 13s%s\n% 13s%s\n\n",
			ls => [ __FILE__,__LINE__, SYNST->[$st], nt => 1,
				'base: ',   $self->cf->get(qw(ldap srch log_base)),
				'scope: ',  'sub',
				'filter: ', $filter ] );
	  $self->l->cc_ldap_err( mesg => $mesg );
	} else {
	  ### here we pop out the latest log record
	  $entry = pop @{[$mesg->sorted]};

	  $self->l->cc( pr => 'debug',
			fm => "%s:%s: LDAP accesslog entry on %s is:\n%s\n% 13s%s\n% 13s%s\n% 13s%s",
			ls => [ __FILE__,__LINE__, SYNST->[$st], $entry->ldif,
				'base: ',   $self->cf->get(qw(ldap srch log_base)),
				'scope: ',  'sub',
				'filter: ', $filter ] )
	    if $self->o('v') > 3;
	}
      } elsif ( $st == LDAP_SYNC_ADD ) { ###-------------------
	$entry = $obj;
      }

      ### picking up a service, the $obj relates to
      my ( $is_ctrl_attr, $ctrl_attr_re, $ctrl_attr_val, $ctrl_srv_re, $s, $svc, $i );
      if ( $st != LDAP_SYNC_DELETE ) {
	foreach $svc ( @{$self->{_opt}{svc}} ) {
	  $is_ctrl_attr = 0;
	  foreach my $ctrl_attr ( @{$self->cf->get('service', $svc, 'ctrl_attr')} ) {

	    if ( my $ctrl_attrs = $obj->get_value( $ctrl_attr, asref => 1 ) ) {
	      $ctrl_attr_re = $self->cf->get('service', $svc, 'ctrl_attr_re');
	      $ctrl_attr_val =
		onlyval { /^.*$ctrl_attr_re.*$/ } @{$ctrl_attrs};
	      if ( defined $ctrl_attr_val ) {
		$is_ctrl_attr++;
	      } else {
		$is_ctrl_attr--;
	      }
	    } else {
	      $is_ctrl_attr--;
	    }

	  }
	  $ctrl_srv_re = $self->cf->get('service', $svc, 'ctrl_srv_re');
	  push @{$s}, $svc
	    if $is_ctrl_attr > 0 && $obj->dn =~ qr/$ctrl_srv_re/;

	}
      } else { ### LDAP_SYNC_DELETE $obj contains only DN
	foreach $svc ( @{$self->{_opt}{svc}} ) {
	  $is_ctrl_attr = 0;
	  foreach my $ctrl_attr ( @{$self->cf->get('service', $svc, 'ctrl_attr')} ) {
	    if ( any
		 {
		   /^$ctrl_attr:.*$/}
		 @{$entry->get_value( 'reqOld', asref => 1 )} ) {
	      $is_ctrl_attr++;
	    } else {
	      $is_ctrl_attr--;
	    }
	  }
	  $ctrl_srv_re = $self->cf->get('service', $svc, 'ctrl_srv_re');
	  push @{$s}, $svc
	    if $is_ctrl_attr > 0 && $entry->get_value('reqDN') =~ qr/$ctrl_srv_re/ &&
	    $is_ctrl_attr == scalar( @{$self->cf->get('service', $svc, 'ctrl_attr')} );
	}
      }

      if ( ! defined $s || scalar(@{$s}) < 1 ) {
	$self->l->cc( pr => 'warning', ls => [ __FILE__,__LINE__, $obj->dn, SYNST->[$st] ],
		      fm => "%s:%s: dn: %s is not configured to be processed on control: %s" )
	  if $self->o('v') > 3;
	return;
      }

=pod

In plugins we use LDAP object to get consequent data, but remember:

=over

=item B<LDAP_SYNC_ADD>

is satisfied with the object provided by search to callback (in
reality it is full data to create new object)

=item B<LDAP_SYNC_MODIFY> and B<LDAP_SYNC_DELETE>

require former data, so, the object provided by search to callback, a
consequent accesslog object is provided as well

=back

=cut

      $self->l->cc( pr => 'debug',
		    fm => "%s:%s: %s obj:%s\nobj_audit:%s",
		    ls => [ __FILE__,__LINE__, SYNST->[$st],
			    $obj->ldif,
			    $entry->ldif ] )
	if $self->o('v') > 3;


      ############################################################
      ####### ---------------------------------------->>>>>>>>> 1
      ############################################################
      if ( $st == LDAP_SYNC_ADD || $st == LDAP_SYNC_MODIFY ) {

	foreach $i ( @{$s} ) {
	  foreach $svc ( @{$self->cf->get('service', $i, 'plugin')} ) {
	    my $opts = {
			cf           => $self->cf,
			force        => $self->o('force'),
			log          => $self->l,
			obj          => $obj,
			obj_audit    => $entry,
			prog         => sprintf("%s v.%s",
						$self->progname,
						$VERSION),
			rdn          => $rdn,
			s            => $i,
			st           => $st,
			synst        => SYNST,
			ts_fmt       => $self->o('ts_fmt'),
			v            => $self->o('v'),
		       };
	    $self->l->cc( pr => 'debug',
			  ls => [ __FILE__,__LINE__, $svc, $opts ],
			  fm => "%s:%s: svc: %s; ldap_sync_add_modify() opts: %s" )
	      if $self->o('v') > 5;
	    App::Regather::Plugin->new( $svc, $opts )->ldap_sync_add_modify;
	  }
	}

	##########################################################
	####### -------------------------------------->>>>>>>>> 2
	##########################################################
      } elsif ( $st == LDAP_SYNC_DELETE ) {

	foreach $i ( @{$s} ) {
	  foreach $svc ( @{$self->cf->get('service', $i, 'plugin')} ) {
	    my $opts = {
			    cf           => $self->cf,
			    force        => $self->o('force'),
			    log          => $self->l,
			    obj          => $obj,
			    obj_audit    => $entry,
			    prog         => sprintf("%s v.%s",
						    $self->progname,
						    $VERSION),
			    rdn          => $rdn,
			    s            => $i,
			    st           => $st,
			    synst        => SYNST,
			    ts_fmt       => $self->o('ts_fmt'),
			    v            => $self->o('v'),
		       };
	    $self->l->cc( pr => 'debug',
			  ls => [ __FILE__,__LINE__, $svc, $opts ],
			  fm => "%s:%s: svc: %s; ldap_sync_delete() opts: %s" )
	      if $self->o('v') > 5;
	    App::Regather::Plugin->new( $svc, $opts )->ldap_sync_delete;
	  }
	}

      }
    } elsif ( defined $syncstate && $syncstate->isa('Net::LDAP::Control::SyncDone') ) {
      $self->l->cc( pr => 'debug', ls => [ __FILE__,__LINE__ ],
		    fm => "%s:%s: Received SYNC DONE CONTROL" )
	if $self->o('v') > 1;
    } elsif ( ! defined $syncstate ) {
      $self->l->cc( pr => 'warning', ls => [ __FILE__,__LINE__ ],
		    fm => "%s:%s: LDAP entry without Sync State control" )
	if $self->o('v') > 1;
    }

    $self->o('req')->cookie($syncstate->cookie) if $syncstate->cookie;

  } elsif ( defined $obj && $obj->isa('Net::LDAP::Intermediate') ) {
    $self->l->cc( pr => 'debug', fm => "%s:%s: Received Net::LDAP::Intermediate\n%s",
		  ls => [ __FILE__,__LINE__, $obj ] )
      if $self->o('v') > 3;
    $self->o('req')->cookie($obj->{'asn'}->{'refreshDelete'}->{'cookie'});
  } elsif ( defined $obj && $obj->isa('Net::LDAP::Reference') ) {
    $self->l->cc( pr => 'debug', fm => "%s:%s: Received Net::LDAP::Reference\n%s",
		  ls => [ __FILE__,__LINE__, $obj ] )
      if $self->o('v') > 3;
    return;
  } else {
    return;
  }
}

1;
