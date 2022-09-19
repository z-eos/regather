# -*- mode: cperl; mode: follow; -*-
#

package App::Regather::Plugin::configfile;

=head1 NAME

configfile - plugin to generate configuration file

=cut

use strict;
use warnings;
use diagnostics;

use POSIX;
use POSIX::Run::Capture qw(:std);
use IPC::Open2;
use File::Temp;
use Template;
use List::MoreUtils qw(onlyval);

use Net::LDAP;
use Net::LDAP::Util qw(generalizedTime_to_time);
use Net::LDAP::Constant qw( LDAP_SYNC_ADD
			    LDAP_SYNC_MODIFY
			    LDAP_SYNC_DELETE );

use constant SYNST => [ qw( LDAP_SYNC_PRESENT LDAP_SYNC_ADD LDAP_SYNC_MODIFY LDAP_SYNC_DELETE ) ];

=head1 METHODS

Each loadable module must provide at least two method: the
constructor B<new> and runtime method B<run>.

=head2 new

Creates an instance of the class and saves a reference to its
arguments for further use.

=cut

sub new {
  my ( $self, $args ) = @_;

  bless {
	 cf           => delete $args->{cf},
	 force        => delete $args->{force},
	 log          => delete $args->{log},
	 obj          => delete $args->{obj},
	 obj_audit    => delete $args->{obj_audit},
	 out_file_old => delete $args->{out_file_old},
	 prog         => delete $args->{prog},
	 rdn          => delete $args->{rdn},
	 service      => delete $args->{s},
	 st           => delete $args->{st},
	 synst        => delete $args->{synst},
	 ts_fmt       => delete $args->{ts_fmt},
	 v            => delete $args->{v},
	 rest         => $args,
	}, $self;
}

sub cf           { shift->{cf} }
sub force        { shift->{force} }
sub log          { shift->{log} }
sub obj          { shift->{obj} }
sub obj_audit    { shift->{obj_audit} }
sub out_file_old { shift->{out_file_old} }
sub rdn          { shift->{rdn} }
sub service      { shift->{service} }
sub syncstate    { shift->{st} }
sub synst        { shift->{synst} }
sub ts_fmt       { shift->{ts_fmt} }
sub v            { shift->{v} }
sub rest         { shift->{rest} }


=head2 ldap_sync_add_modify

method to manipulate config files on

=over

=item B<LDAP_SYNC_ADD>

create

=item B<LDAP_SYNC_MODIFY>

=over

=item B<reqType=modify>

modify

=item B<reqType=modrdn>

delete F<reqOld: cn> config file and create new

=back

=back

=cut

sub ldap_sync_add_modify {
  my $self = shift;

  my ($tt_vars, $pp, $chin, $chou, $chst, $cher);

  $self->log->cc( pr => 'debug', fm => "%s:%s: called with arguments: %s",
		  ls => [ __FILE__,__LINE__, join(',', sort(keys( %{$self}))), ] )
    if $self->{v} > 3;

  my $out_file_old;
  if ( $self->syncstate == LDAP_SYNC_MODIFY &&
       $self->obj_audit->get_value('reqType') eq 'modrdn' ) {
    $out_file_old =
      (
       split( / /,
	      onlyval { /^cn: .*$/ } @{$self->obj_audit->get_value('reqOld', asref => 1)} )
      )[1];
  }

  ### PREPARING OUTPUT RELATED VARIABLES
  my %out_paths = out_paths( $self );

  return if ! %out_paths;
  my $out_file_pfx //= $out_paths{out_file_pfx};
  my $out_file     //= $out_paths{out_file};
  my $dir          = $out_file_pfx // $self->cf->get('service', $self->service, 'out_path');
  my $out_to       = $dir . '/' . $out_file;

  $self->log->cc( pr => 'debug', fm => "%s:%s: output directory: %s; file: %s",
		  ls => [ __FILE__,__LINE__, $dir, $out_file ] )
    if $self->{v} > 3;

  ### on modrdn two events occure
  ### 1. obj->cn differs of obj_audit->reqOld->cn
  ### 2. obj->cn equals  of obj_audit->reqOld->cn
  ###    and it is the right moment to delete only
  ###    reqOld file

  if ( defined $out_file_old && $out_file_old eq $self->obj->get_value('cn') ) {
    if ( unlink $dir . '/' . $out_file_old ) {
      $self->log->cc( pr => 'info', fm => "%s:%s: file %s/%s deleted (on ModRDN)",
		      ls => [ __FILE__,__LINE__, $dir, $out_file_old ] );
    } else {
      $self->log->cc( pr => 'err',
		      fm => "%s:%s: %s/%s not removed (on ModRDN); error: %s",
		      ls => [ __FILE__,__LINE__, $dir,
			      $out_file_old, $! ], nt => 1, );
    }
    return;
  }

  ### COLLECTING ALL MAPPED ATTRIBUTES VALUES
  foreach my $i ( ( 'm', 's') ) {
    if ( $self->cf->is_section('service', $self->service, 'map', $i) ) {
      foreach my $j ( $self->cf->names_of('service',
					  $self->service,
					  'map', $i) ) {
	if ( $i eq 's' &&
	     ! $self->obj->exists( $self->cf->get('service',
						  $self->service,
						  'map', $i, $j)) ) {
	  if ( $self->cf->get(qw(core dryrun)) ) {
	    $self->log->cc( pr => 'debug',
			    fm => "%s:%s: DRYRUN: %s to delete (no attr: %s)",
			    ls => [ __FILE__,__LINE__, $out_to,
				    $self->cf->get('service',
						   $self->service,
						   'map', $i, $j)
				  ] );
	  } else {
	    if ( unlink $out_to ) {
	      $self->log->cc( pr => 'debug',
			      fm => "%s:%s: file %s deleted (no attr: %s)",
			      ls => [ __FILE__,__LINE__, $out_to,
				      $self->cf->get('service',
						     $self->service,
						     'map', $i, $j)
				    ] )
		if $self->{v} > 0;
	    } else {
	      $self->log->cc( pr => 'err', nt => 1,
			      fm => "%s:%s: %s not removed (no attr: %s); error: %s",
			      ls => [ __FILE__,__LINE__, $out_to,
				      $self->cf->get('service',
						     $self->service,
						     'map', $i, $j), $!
				    ] );
	    }
	  }

	  ### if any of `map s` attributes doesn't exist, we delete
	  ### that config file preliminaryly and skip that attribute
	  ### from been processed by Template
	  next;

	} elsif ( $i eq 'm' && $self->obj->exists( $self->cf->get('service', $self->service, 'map', $i, $j)) ) {
	  $tt_vars->{$j} = $self->obj->get_value( $self->cf->get('service', $self->service, 'map', $i, $j),
					    asref => 1 );
	} else {
	  if ( $j =~ /certificateRevocationList/ ) {
	    $tt_vars->{$j} =
	      opensslize({ in => $self->obj->get_value( $self->cf->get('service', $self->service, 'map', $i, $j) ) });
	  } elsif ( $j =~ /cACertificate/ ) {
	    $tt_vars->{$j} =
	      opensslize({ cmd => 'x509',
			   in  => $self->obj->get_value( $self->cf->get('service', $self->service, 'map', $i, $j) ),
			   log => $self->log,
			   v => $self->{v} });
	  } else {
	    $tt_vars->{$j} = $self->obj->get_value( $self->cf->get('service', $self->service, 'map', $i, $j) ) // 'NA';
	  }
	}
      }
    }
  }

  $tt_vars->{prog}       = $self->{prog};
  $tt_vars->{DN}         = $self->obj->dn;
  $tt_vars->{date}       = strftime( $self->{ts_fmt}, localtime(time));
  $tt_vars->{descr}      = $self->obj->get_value('description')
    if $self->obj->exists('description');
  $tt_vars->{server}     = ( split(/\@/, $self->obj->get_value('authorizedService')) )[1]
    if $self->obj->exists('authorizedService');
  $tt_vars->{createdby}  =
    $self->obj->exists('creatorsName') ?
    ( split(/=/, ( split(/,/, $self->obj->get_value('creatorsName')) )[0]) )[1] :
    'UNKNOWN';
  $tt_vars->{modifiedby} =
    $self->obj->exists('modifiersName') ?
    ( split(/=/, ( split(/,/, $self->obj->get_value('modifiersName')) )[0]) )[1] :
    'UNKNOWN';

  if ( ! $self->force && -e $out_to &&
       ( generalizedTime_to_time($self->obj->get_value('modifyTimestamp'))
	 <
	 (stat($out_to))[9] ) ) {
    $self->log->cc( pr => 'debug',
	      fm => "%s: skip. object %s is older than target file %s, (object modifyTimestamp: %s is older than file mtime: %s",
	      ls => [ sprintf("%s:%s",__FILE__,__LINE__), $self->obj->dn, $out_to,
		      strftime( "%F %T",
				localtime(generalizedTime_to_time($self->obj->get_value('modifyTimestamp')))),
		      strftime( "%F %T", localtime((stat($out_to))[9])),
		    ] )
      if $self->{v} > 0;
    return;
  }

  ### PICKING ROOT OBJECT RDN (IN OUR CASE IT IS "UID")
  foreach ( reverse split(/,/, $self->obj->dn) ) {
    next if $_ !~ /^uid=/;
    $tt_vars->{uid} = ( split(/=/, $_) )[1];
    last;
  }

  ### DRYRUN
  if ( $self->cf->get(qw(core dryrun)) ) {

    $self->log->cc( pr => 'debug', fm => "%s: DRYRUN: %s -> %s",
	      ls => [ sprintf("%s:%s",__FILE__,__LINE__),
		     sprintf("%s/%s", $self->cf->get(qw(core tt_path)),
			     $self->cf->get('service', $self->service, 'tt_file')),
		     $dir. '/' . $out_file
		    ] );

    if ( $self->cf->is_set($self->service, 'chmod') ) {
      $self->log->cc( pr => 'err', fm => "%s: DRYRUN: chmod %s, %s",
		ls => [ sprintf("%s:%s",__FILE__,__LINE__), $self->cf->get('service', $self->service, 'chmod'), $out_to ] );
    } elsif ( $self->cf->is_set(qw(core chmod)) ) {
      $self->log->cc( pr => 'err', fm => "%s: DRYRUN: chmod %s, %s",
		ls => [ sprintf("%s:%s",__FILE__,__LINE__), $self->cf->get('core', 'chmod'), $out_to ] );
    }

    if ( $self->cf->is_set($self->service, 'chown') ) {
      $self->log->cc( pr => 'err', fm => "%s: DRYRUN: chown %s, %s, %s",
		ls => [ sprintf("%s:%s",__FILE__,__LINE__), $self->obj->get_value('uidNumber'),
			$self->obj->get_value('gidNumber'),
			$out_to ] );
    }
    return;
  }

  my ( $tmp_fh, $tmp_fn );
  eval { $tmp_fh = File::Temp->new( UNLINK => 0, DIR => $dir ); };
  if ( $@ ) {
    $self->log->cc( pr => 'err', fm => "%s: File::Temp->new( DIR => %s ); service \"%s\"; err: \"%s\"",
	      ls => [ sprintf("%s:%s",__FILE__,__LINE__), $dir, $self->service, $@ ] );
    return;
  }
  $tmp_fn = $tmp_fh->filename;
  my $tt = Template->new( TRIM        => $self->cf->get(qw(core tt_trim)),
			  ABSOLUTE    => 1,
			  RELATIVE    => 1,
			  OUTPUT_PATH => $dir,
			  DEBUG       => $self->log->foreground // $self->cf->get(qw(core tt_debug)) );

  $self->log->cc( pr => 'err', fm => "%s: Template->new( OUTPUT_PATH => %s ) for service %s error: %s",
	    ls => [ sprintf("%s:%s",__FILE__,__LINE__), $dir, $self->service, $! ] )
    if ! defined $tt;

  $tt->process( sprintf("%s/%s",
			$self->cf->get(qw(core tt_path)),
			$self->cf->get('service', $self->service, 'tt_file')),
		$tt_vars,
		$tmp_fh ) || do {
		  $self->log->cc( pr => 'err', fm => "%s: %s .tt process error: %s",
			    ls => [ sprintf("%s:%s",__FILE__,__LINE__), SYNST->[$self->syncstate], $tt->error ] );
		  return;
		};

  close( $tmp_fh ) || do {
    $self->log->cc( pr => 'err',
		    fm => "%s:%s: close file (opened for writing), service %s, failed: %s",
	      ls => [ __FILE__,__LINE__, $self->service, $! ] );
    next;
  };

  if ( $self->cf->get(qw(core dryrun)) ) {
    $self->log->cc( pr => 'debug', fm => "%s: DRYRUN: rename %s should be renamed to %s",
	      ls => [ sprintf("%s:%s",__FILE__,__LINE__), $tmp_fn, $out_file ] );
  } else {
    rename $tmp_fn, $out_to ||
      $self->log->cc( pr => 'err', fm => "%s: rename %s to %s, failed",
		ls => [ sprintf("%s:%s",__FILE__,__LINE__), $tmp_fn, $out_to ] );

    if ( -e $out_to ) {
      if ( $self->cf->is_set('service', $self->service, 'chmod') ) {
	chmod oct($self->cf->get('service', $self->service, 'chmod')), $out_to ||
	  $self->log->cc( pr => 'err', fm => "%s: chmod for %s failed",
		    ls => [ sprintf("%s:%s",__FILE__,__LINE__), $out_to ] );
      } elsif ( $self->cf->is_set(qw(core chmod)) ) {
	chmod oct($self->cf->(qw(core chmod))), $out_to ||
	  $self->log->cc( pr => 'err', fm => "%s: chmod for %s failed",
		    ls => [ sprintf("%s:%s",__FILE__,__LINE__), $out_to ] );
      }

      if ( $self->cf->is_set('service', $self->service, 'chown') ) {
	chown $self->obj->get_value('uidNumber'),
	  $self->obj->get_value('gidNumber'),
	  $out_to ||
	  $self->log->cc( pr => 'err', fm => "%s: chown (%s:%s) %s failed",
		    ls => [ sprintf("%s:%s",__FILE__,__LINE__), $self->obj->get_value('uidNumber'),
			    $self->obj->get_value('gidNumber'),
			    $out_to ] );
      }
    } else {
      $self->log->cc( pr => 'err', fm => "%s: %s disappeared, no such file any more...",
		ls => [ sprintf("%s:%s",__FILE__,__LINE__), $out_to ] );
    }
  }
  $self->log->cc( pr => 'info', fm => "%s: control %s: dn: %s processed successfully.",
		  ls => [ sprintf("%s:%s",__FILE__,__LINE__), SYNST->[$self->syncstate], $self->obj->dn ] )
    if $self->{v};

  if ( $self->cf->is_set('service', $self->service, 'post_process') ) {
    foreach $pp ( @{$self->cf->get('service', $self->service, 'post_process')} ) {
      my $pid = open2( $chou, $chin, $pp );
      waitpid( $pid, 0 );
      $chst = $? >> 8;
      if ( $chst ) {
	$cher .= $_ while ( <$chou> );
	$self->log->cc( pr => 'err', ls => [ sprintf("%s:%s",__FILE__,__LINE__), $self->service, $pp, $cher ], nt => 1,
		  fm => "%s: service %s post_process: %s, error: %s", );
      }
    }
  }
}

=head2 ldap_sync_delete

performs deletion of an existent config file on B<LDAP_SYNC_DELETE>

=cut

sub ldap_sync_delete {
  my $self = shift;

  my ($tt_vars, $pp, $chin, $chou, $chst, $cher);

  $self->log->cc( pr => 'debug', fm => "%s:%s: %s called with arguments: %s",
		  ls => [ __FILE__,__LINE__, join(',', sort(keys( %{$self}))), ] )
    if $self->{v} > 3;

  ### PREPARING OUTPUT RELATED VARIABLES
  # my %out_paths = out_paths( cf => $self->cf, obj => $self->obj, rdn => $self->rdn,
  # 			     syncstate => $self->syncstate, synst => $self->synst, 
  # 			     obj_audit => $self->obj_audit, service => $self->service,
  # 			     log => $self->log );
  my %out_paths = out_paths( $self );
  return if ! %out_paths;
  my $out_file_pfx //= $out_paths{out_file_pfx};
  my $out_file     //= $out_paths{out_file};
  my $dir          = $out_file_pfx // $self->cf->get('service', $self->service, 'out_path');
  my $out_to       = $dir . '/' . $out_file;

  $self->log->cc( pr => 'debug', fm => "%s:%s: output directory: %s; file: %s",
	    ls => [ __FILE__,__LINE__, $dir, $out_file ] ) if $self->{v} > 3;

  if ( $self->cf->get(qw(core dryrun)) ) {
    $self->log->cc( pr => 'debug', fm => "%s:%s: DRYRUN: file %s should be deleted",
	      ls => [ __FILE__,__LINE__, $out_to ] );
  } else {
    if ( unlink $out_to ) {
      $self->log->cc( pr => 'info', fm => "%s:%s: file %s was successfully deleted",
		ls => [ __FILE__,__LINE__, $out_to ] )
	if $self->{v};
    } else {
      $self->log->cc( pr => 'err', fm => "%s: file %s was not removed; error: %s",
		ls => [ sprintf("%s:%s",__FILE__,__LINE__), $out_to, $! ] );
    }
  }
  $self->log->cc( pr => 'debug', fm => "%s:%s: control %s: dn: %s processing finished",
		  ls => [ __FILE__,__LINE__, SYNST->[$self->syncstate], $self->obj->dn ] )
    if $self->{v} > 0;

  if ( $self->cf->is_set('service', $self->service, 'post_process') ) {
    foreach $pp ( @{$self->cf->get('service', $self->service, 'post_process')} ) {
      my $pid = open2( $chou, $chin, $pp );
      waitpid( $pid, 0 );
      $chst = $? >> 8;
      if ( $chst ) {
	$cher .= $_ while ( <$chou> );
	$self->log->cc( pr => 'err', nt => 1,
			ls => [ __FILE__,__LINE__, $self->service, $pp, $cher ],
			fm => "%s:%s: service %s post_process: %s, error: %s", );
      }
    }
  }

}

=head2 B<out_paths>

method to construct otput full path for situations

=over

=item 1. B<out_file_pfx> and B<out_file>

concatenation

=item 2. not B<out_file_pfx> and B<out_file>

F<out_file> can contain absolute path

=item 3. neither B<out_file_pfx> nor B<out_file>

value can be provided with I<rdn_val> or attribute I<rdn> value of the
object processed, is used

=back

=cut

sub out_paths {
  my $self = shift;

  my ($out_file_pfx, $out_file, $rdn, $rdn_val, $re );

  my $reqOld  = $self->obj_audit->get_value('reqOld', asref => 1)
    if $self->syncstate == LDAP_SYNC_DELETE;

  if ( $self->cf->is_set('service', $self->service, 'out_file_pfx') &&
       $self->cf->is_set('service', $self->service, 'out_file') ) {

    if ( $self->syncstate == LDAP_SYNC_DELETE ) { ###------------------------------

      $re = $self->cf->get('service', $self->service, 'out_file_pfx');
      $out_file_pfx = (
		       split( / /, onlyval { /^$re.*$/ } @{$reqOld} )
		      )[1];
    } else {
      $out_file_pfx = $self->obj_audit->get_value($self->cf->get('service',
							   $self->service,
							   'out_file_pfx'));
    }

    $out_file_pfx = substr($out_file_pfx, 1) if $self->cf->is_set(qw(core altroot));
    if ( ! -d $out_file_pfx ) {
      $self->log->cc( pr => 'err', fm => "%s: service %s, target directory %s doesn't exist",
		   ls => [ sprintf("%s:%s",__FILE__,__LINE__), $self->service, $out_file_pfx ] );
      return ();
    } else {
      $out_file = sprintf("%s%s",
			  $self->cf->get('service', $self->service, 'out_file'),
                          $self->cf->get('service', $self->service, 'out_ext') // '');
    }

  } elsif ( ! $self->cf->is_set('service', $self->service, 'out_file_pfx') &&
            $self->cf->is_set('service', $self->service, 'out_file')) {

    $out_file = sprintf("%s%s",
			$self->cf->get('service', $self->service, 'out_file'),
                        $self->cf->get('service', $self->service, 'out_ext') // '');

  } elsif ( ! $self->cf->is_set('service', $self->service, 'out_file_pfx') &&
            ! $self->cf->is_set('service', $self->service, 'out_file')) {

    if ( $self->syncstate == LDAP_SYNC_DELETE ) { ###------------------------------

      $re = $self->rdn;
      $rdn_val = (
		  split( / /, onlyval { /^${re}:.*$/ } @{$reqOld} )
		 )[1];
    } else {
      $rdn_val = $self->obj->get_value($self->rdn);
    }

    $out_file = sprintf("%s%s",
			$rdn_val,
                        $self->cf->get('service', $self->service, 'out_ext') // '');
  }

  return ( out_file_pfx => $out_file_pfx, out_file => $out_file );
}

=head2 opensslize

method toconvert between openssl cert formats

=cut

sub opensslize {
  my $args = shift;
  my $arg = { cmd     => $args->{cmd}     // 'crl',
	      in      => $args->{in},
	      inform  => $args->{inform}  // 'DER',
	      outform => $args->{outform} // 'PEM',
	      log     => $args->{log}
	    };

  my $obj = POSIX::Run::Capture( argv => [
					  '/usr/bin/openssl',
					  $arg->{cmd},
					  '-inform',  $arg->{inform},
					  '-outform', $arg->{outform}
					 ] );

  $arg->{log}->cc( pr => 'err', ls => [ __FILE__, __LINE__, $obj->errno ],
		   fm => "%s:%s: opensslize() error: %s" )
    if ! $obj->run;

  $arg->{res} =  join '', @{$obj->get_lines(SD_STDOUT)};

  return $arg->{res};
}

######################################################################

1;
