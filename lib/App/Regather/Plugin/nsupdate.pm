# -*- mode: cperl; mode: follow; -*-
#

package App::Regather::Plugin::nsupdate;

=head1 NAME

nsupdate - RFC2136 complaint DNS zone update

=cut

=head1 DESCRIPTION

plugin to update dynamis DNS zone

=cut

use strict;
use warnings;
use diagnostics;

use Socket;
use List::MoreUtils qw(onlyval);
use Net::DNS;
use Net::DNS::RR::TSIG;
use Net::LDAP;
use Net::LDAP::Constant qw( LDAP_SYNC_ADD
			    LDAP_SYNC_MODIFY
			    LDAP_SYNC_DELETE );

use constant { UPDATE_UNKNOWN => 0,
	       UPDATE_SUCCESS => 1,
	       UPDATE_ERROR   => 2  };

=head1 METHODS

=head2 new

Creates an instance of the class and saves a reference to its
arguments for further use.

=cut

sub new {
  my $class = shift;
  local %_ = %{$_[0]};

  $_{log}->cc( pr => 'debug', fm => "%s: service %s; called for dn: %s",
	       ls => [ sprintf("%s:%s",__FILE__,__LINE__),
		       $_{s}, $_{obj}->dn, ] )
    if $_{v} > 5;

  my $ns_txt_pfx = $_{cf}->get('service', $_{s}, 'ns_txt_pfx');
  my $re         = qr/^$ns_txt_pfx/;
  my $ns_attr_ip = $_{cf}->get('service', $_{s}, 'ns_attr_ip');
  my $ns_attr    = $_{cf}->get('service', $_{s}, 'ns_attr');

  my $resolver = new Net::DNS::Resolver;

  my ( @z, @zones, $query, $zone, $fqdn, @rr, @rr_types, @servers,
       $ip, $ip_old, $ctrl_attr_re,
       $hostname, $hostname_old, $reqOld, $reqMod, $reqType );

=item 1. get NS-es

should be provided

=cut

  if ($_{cf}->is_set('service', $_{s}, 'ns_server')) {
    push @servers, $_{cf}->get('service', $_{s}, 'ns_server');
  } else {
    $_{log}->cc( pr => 'err',
		 fm => "%s: can't get ns_server value",
		 ls => [ sprintf("%s:%s",__FILE__,__LINE__), ] );
    return;
  }

  if ($_{cf}->is_set('service', $_{s}, 'ns_rr_type')) {
    push @rr_types, $_{cf}->get('service', $_{s}, 'ns_rr_type');
  } else {
    $_{log}->cc( pr => 'err',
		 fm => "%s: can't get ns_rr_type value",
		 ls => [ sprintf("%s:%s",__FILE__,__LINE__), ] );
    return;
  }

=item 2. init resolver

=cut

  $resolver->
    nameservers(
		map {
		  if (my @addrs = gethostbyname($_)) {
		    my @ret = map { inet_ntoa($_) } @addrs[4 .. $#addrs];
		  } else { $_ }
		} @servers
	       );

=item 3. get zone/s to update

should be provided

=cut

  if ($_{cf}->is_set('service', $_{s}, 'ns_zone')) {
    push @zones, $_{cf}->get('service', $_{s}, 'ns_zone');
  } else {
    $_{log}->cc( pr => 'err', fm => "%s:%s: %s: no ns_zone set",
		 ls => [ __FILE__,__LINE__,  $_{synst}->[$_{st}] ] );
    return;
  }

=item 4. get target ip address and hostname from LDAP obj

=over

=item B<LDAP_SYNC_ADD>

obj is a common objec

=item B<LDAP_SYNC_DELETE> and B<LDAP_SYNC_MODIFY>

obj is accesslog object

=back

=cut

  $ctrl_attr_re = $_{cf}->get('service', $_{s}, 'ctrl_attr_re');

  if ( $_{st} == LDAP_SYNC_ADD ) { ###----------------------------

    $hostname_old = $hostname = $_{obj}->get_value($ns_attr);

    if ($ns_attr_ip eq 'umiOvpnCfgIfconfigPush') {
      $ip =
	(split( / /, $_{obj}->get_value($ns_attr_ip) )
	)[0];
    } elsif ($ns_attr_ip eq 'dhcpStatements') {

      $ip = (
	     split( / /,
		    onlyval
		    { /^$ctrl_attr_re.*$/ }
		    @{$_{obj}->get_value($ns_attr_ip, asref => 1)} )
	    )[1];
    } else {
      $ip = $_{obj}->get_value($ns_attr_ip);
    }

    $ip_old = $ip;

  } elsif ( $_{st} == LDAP_SYNC_DELETE ) { ###--------------------

    $reqType = $_{obj_audit}->get_value('reqType');
    $reqOld  = $_{obj_audit}->get_value('reqOld', asref => 1);

    $hostname = (
		 split( / /, onlyval { /^$ns_attr.*$/ } @{$reqOld} )
		)[1];

    $ip = (
	   split( / /, onlyval { /^$ns_attr_ip.*$/ } @{$reqOld} )
	  )[1];

  } elsif ( $_{st} == LDAP_SYNC_MODIFY ) { ###--------------------

    $reqType = $_{obj_audit}->get_value('reqType');
    $reqOld  = $_{obj_audit}->get_value('reqOld', asref => 1);
    $reqMod  = $_{obj_audit}->get_value('reqMod', asref => 1);

=pod

we skip all if modified object doesnt contain I<ns_attr_ip> attribute and the modification type is not I<modify>

modified object doesnt contain I<ns_attr_ip> attribute either when the attribute is unchanged or when modification type was I<modrdn> and in last case we have hostname changed

besides that, we expect I<RDDN> of object be a hostname

=cut

    ### !! TO FINISH, NOT READY FOR MULTIPLE ZONES IN CONFIG
    if ( $_{obj_audit}->get_value('reqType') eq 'modrdn' ) {

      $hostname     = (split(/=/, $_{obj_audit}->get_value('reqNewRDN')))[1];
      $hostname_old = ( split( / /, onlyval { /^$ns_attr.*$/ } @{$reqOld} ) )[1];

      $_{log}->cc( pr => 'debug',
		   fm => "%s:%s: %s: hostname: %s; old: %s",
		   ls => [ __FILE__,__LINE__, $_{synst}->[$_{st}],
			   $hostname, $hostname_old ] )
	if $_{v} > 3;

      $fqdn = join('.', $hostname_old, $zones[0], '');
      $query = $resolver->query( $fqdn,	'A');
      if ($query) {
	@rr = $query->answer;
	$ip = $ip_old = $rr[0]->address;

	$_{log}->cc( pr => 'debug',
		     fm => "%s:%s: %s: resolver query domain: %s; type: A; RR: %s",
		     ls => [ __FILE__,__LINE__, $_{synst}->[$_{st}], $fqdn, $ip_old ] )
	  if $_{v} > 3;

      } else {
	$_{log}->cc( pr => 'warning',
		     fm => "%s:%s: %s: unable to resolve %s record: A; error: %s",
		     ls => [ __FILE__,__LINE__, $_{synst}->[$_{st}], $fqdn,
			     $resolver->errorstring, ] );
      }

    } else {

      return if ! onlyval { /^$ns_attr_ip.*$/ } @{$reqMod};

      if ($ns_attr_ip eq 'umiOvpnCfgIfconfigPush') {
	$ip = (
	       split( / /, onlyval { /^$ns_attr_ip.*$/ } @{$reqMod} )
	      )[1];
      } elsif ($ns_attr_ip eq 'dhcpStatements') {
	$ip = (
	       split( / /, onlyval { /^fixed-address.*$/ } @{$reqMod} )
	      )[2];
	$ip_old = (
		   split( / /, onlyval { /^.*fixed-address.*$/ } @{$reqOld} )
		  )[2];

      } else {

	$ip = (
	       split( / /, onlyval { /^$ns_attr_ip.*$/ } @{$reqMod} )
	      )[1];
	$ip_old = (
		   split( / /, onlyval { /^$ns_attr_ip.*$/ } @{$reqOld} )
		  )[1];

      }

      ### it's not clear, whether $ns_attr attribute is present in each
      ### reqType=modify object
      $hostname = $hostname_old =
	(
	 split( / /, onlyval { /^$ns_attr.*$/ } @{$reqOld} )
	)[1];

    }

  }

  $_{log}->cc( pr => 'err',
	       fm => "%s:%s: %s: ip: %s is undefined or malformed",
	       ls => [ __FILE__,__LINE__, $_{synst}->[$_{st}], $ip ] )
    if ! defined $ip || $ip !~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

  $_{log}->cc( pr => 'err',
	       fm => "%s:%s: %s: ip_old: %s is undefined or malformed",
	       ls => [ __FILE__,__LINE__, $_{synst}->[$_{st}], $ip_old ] )
    if ! defined $ip_old || $ip_old !~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

  $_{log}->cc( pr => 'err',
	       fm => "%s:%s: %s: domain name is undefined or empty",
	       ls => [ __FILE__,__LINE__, $_{synst}->[$_{st}], $hostname_old ] )
    if ! defined $hostname_old || $hostname_old eq '';


  bless {
	 cf         => delete $_{cf},
	 force      => delete $_{force},
	 log        => delete $_{log},
	 obj        => delete $_{obj},
	 obj_audit  => delete $_{obj_audit},
	 service    => delete $_{s},
	 st         => delete $_{st},
	 synst      => delete $_{synst},
	 v          => delete $_{v},

	 hostname     => $hostname,
	 hostname_old => $hostname_old // undef,
	 ip           => $ip,
	 ip_r         => join('.', @{[ reverse( @{[ split(/\./, $ip) ]} ) ]}),
	 reqType      => $reqType,
	 resolver     => $resolver,
	 rr_types     => \@rr_types,
	 servers      => \@servers,
	 zones        => \@zones,

	 rest         => \%_,
	}, $class;

}

sub cf            { shift->{cf} }
sub force         { shift->{force} }
sub hostname      { shift->{hostname} }
sub hostname_old  { shift->{hostname_old} }
sub ip            { shift->{ip} }
sub ip_r          { shift->{ip_r} }
sub log           { shift->{log} }
sub obj           { shift->{obj} }
sub obj_audit     { shift->{obj_audit} }
sub resolver      { shift->{resolver} }
sub rr_types      { shift->{rr_types} }
sub service       { shift->{service} }
sub servers       { shift->{servers} }
sub syncstate     { shift->{st} }
sub synst         { shift->{synst} }
sub v             { shift->{v} }
sub zones         { shift->{zones} }

=head2 ldap_sync_add_modify

performs nsupdate: add new, delete or modify existent records,
according LDAP sync state

=cut

sub ldap_sync_add_modify {
  my $self = shift;

  $self->log->cc( pr => 'debug',
		  fm => "%s:%s: service %s; called for dn: %s",
		  ls => [ __FILE__,__LINE__, $self->service, $self, ] )
    if $self->v > 5;

  my ( $update, $query, @rr, $rr_type, $tmp, $reply, $zone, $param, $num, $res );
  $res = '';
  foreach $zone ( @{$self->zones} ) {

    $update = new Net::DNS::Update($zone);

    foreach $rr_type ( @{$self->rr_types} ) {

      $param->{type} = $rr_type;
      if ( lc($rr_type) eq 'ptr' ) {
	$param->{fqdn} = sprintf('%s.%s', $self->ip_r, $zone);
	$param->{rr_add} =
	  sprintf("%s %s %s %s.%s.",
		  $param->{fqdn},
		  $self->cf->get('service', $self->service, 'ns_ttl'),
		  $param->{type}, $self->hostname, $zone );
      } elsif ( lc($rr_type) eq 'a' ) {
	$param->{fqdn} = sprintf("%s.%s", $self->hostname, $zone);
	$param->{rr_add} = sprintf("%s. %s %s %s",
				   $param->{fqdn},
				   $self->cf->get('service', $self->service, 'ns_ttl'),
				   $param->{type},
				   $self->ip);
      }

      $query = $self->resolver->query($param->{fqdn}, $param->{type});
      if ($query) {
	@rr = $query->answer;
	$param->{rr} =
	  $param->{type} eq 'A' ? $rr[0]->address : $rr[0]->ptrdname;

	$self->log->cc( pr => 'debug',
			fm => "%s:%s: resolver query domain: %s; type: %s; RR: %s",
			ls => [ __FILE__,__LINE__, $param->{fqdn},
				$param->{type}, $param->{rr} ] )
	  if $self->v > 3;

      } else {
	$self->log->cc( pr => 'warning',
			fm => "%s: unable to resolve %s record: %s; error: %s",
			ls => [ sprintf("%s:%s",__FILE__,__LINE__),
				$param->{type}, $param->{fqdn},
				$self->resolver->errorstring, ] );
      }

      $self->log->cc( pr => 'debug', fm => "%s: state: %s; fqdn: %s",
		      ls => [ sprintf("%s:%s",__FILE__,__LINE__),
			      $self->syncstate, $param->{fqdn} ] )
	 if $self->v > 3;

      if ( $self->syncstate == LDAP_SYNC_ADD ||
	   $self->syncstate == LDAP_SYNC_MODIFY ) {

	$num = $update->push( update =>
			      rr_del($param->{fqdn}),
			      rr_add($param->{rr_add})
			    );

	$res .= sprintf(" rr_del: %s; rr_add: %s; ", $param->{fqdn}, $param->{rr_add});

	$self->log->cc( pr => 'info',
			fm => "%s: %s: Net::DNS resources to update: %s; rr_del: %s; rr_add: %s",
			ls => [ sprintf("%s:%s",__FILE__,__LINE__),
				$self->syncstate == 1 ? 'LDAP_SYNC_ADD' : 'LDAP_SYNC_MODIFY',
				$num, $param->{rr_add}, $param->{fqdn} ] );

      } elsif ( $self->syncstate == LDAP_SYNC_DELETE ) {

	$num = $update->push( update => rr_del( $param->{fqdn}) );

	$res .= sprintf(" rr_del: %s;", $param->{fqdn});

	$self->log->cc( pr => 'info',
			fm => "%s: LDAP_SYNC_DELETE: Net::DNS resources to update: %s; rr_del: %s",
			ls => [ sprintf("%s:%s",__FILE__,__LINE__), $num,
				$param->{fqdn} ] );

      } else {
	$self->log->cc( pr => 'debug', fm => "%s: nothing to update",
			ls => [ sprintf("%s:%s",__FILE__,__LINE__) ] );
	next;
      }

    }

    $update->sign_tsig($self->cf->get('service', $self->service, 'ns_keyfile'))
      if $self->cf->is_set('service', $self->service, 'ns_keyfile');

    $self->log->cc( pr => 'debug', fm => "%s:%s: Net::DNS update->string to send:\n%s\n",
		    ls => [ __FILE__,__LINE__, $update->string ] )
      if $self->v > 3;

    $reply = $self->resolver->send($update);

    $self->log->cc( pr => 'debug', fm => "%s:%s: Net::DNS resolver reply:\n%s\n",
		    ls => [ __FILE__,__LINE__, $reply->string ] )
      if $self->v > 3;

    if ($reply) {
      if ( $reply->header->rcode eq 'NOERROR' ) {
	$self->log->cc( pr => 'info',
			fm => "%s:%s: %s: update successful; %s",
			ls => [ __FILE__,__LINE__, $self->synst->[$self->syncstate],
				$res ] );
      } else {
	$self->log->cc( pr => 'err',
			fm => "%s:%s: %s: update failed; %s: %s",
			ls => [ __FILE__,__LINE__, $self->synst->[$self->syncstate],
				$res, $reply->header->rcode ] );
      }
    } else {
      $self->log->cc( pr => 'err',
		      fm => "%s:%s: %s: update failed; %s: %s",
		      ls => [ __FILE__,__LINE__, $self->synst->[$self->syncstate],
			      $res, $self->resolver->errorstring ] );
    }

    undef @rr;
    undef $update;
    undef $param;
    undef $reply;
    undef $res;

  }
}

=head2 ldap_sync_delete

alias to ldap_sync_add_modify

=cut

sub ldap_sync_delete { goto &ldap_sync_add_modify }

######################################################################

1;
