# -*- mode: cperl; mode: follow; -*-
#

package Regather::Logg;

use strict;
use warnings;
use diagnostics;
use Sys::Syslog qw(:standard :macros);
use Data::Printer caller_info => 1, class => { expand => 2 };

sub new {
  my $class           = shift;
  local %_            = @_;
  my $self            = bless {}, $class;
  $self->{prognam}    = $_{prognam};
  $self->{foreground} = $_{foreground} // 0;
  $self->{colors}     = $_{colors}     // 0;
  $self->{ts_fmt}     = "%a %F %T %Z (%z)";

  openlog($self->{prognam}, "ndelay,pid");

  $self
}

=head2 logg

wrapper to log to syslog or stdin. On input it expects hash

    fg => foreground: stdin or syslog
    pr => priority: level[|facility]
    fm => format: sprintf format
    ls => list of values to be sprintf-ed with format fm

=cut

sub logg {
  my ( $self, $args ) = @_;
  my $arg = { pr   => $args->{pr} // 'info',
	      pr_s => sprintf("%s|%s",
			      $args->{pr}, $self->{facility} // 'local4'),
	      pr_f => sprintf("<%s:%s> ",
			      $self->{facility} // 'CONFIG FILE PARSE', $args->{pr}),
	      fm   => $args->{fm}, };

  if ( exists $args->{ls} ) {
    @{$arg->{ls}} = map { ref && ref ne 'SCALAR' ? np($_, caller_info => 0) : $_ } @{$args->{ls}};
  } else {
    $arg->{ls} = [];
  }

  if ( $self->{foreground} ) {
    $arg->{msg} = sprintf $arg->{pr_f} . $arg->{fm}, @{$arg->{ls}};
    p($arg->{msg}, colored => $self->{colors} && $self->{foreground}, caller_info => 0 );
  } else {
    syslog( $arg->{pr_s}, $arg->{pr_f} . $arg->{fm}, @{$arg->{ls}} );
  }
}

sub set_m {
  my ( $self, $cf ) = @_;
  if ( ref($cf) eq 'HASH' ) {
    while ( my ( $k, $v ) = each %$cf ) {
      next if exists $self->{$k};
      $self->{$k} = $v;
    }
  } else {
    $self->logg({ pr => 'err',
		  fm => "Logg::set_m(): argument supplied is not HASH ..." });
    return 0;
  }
}

sub set {
  my ( $self, $k, $v ) = @_;
  $self->{$k} = $v;
}

sub get {
  my ( $self, $k ) = @_;
  if ( exists $self->{$k} ) {
    $self->{$k};
  } else {
    $self->logg({ pr => 'err',
		  fm => "attribute \"%s\" doesn't exist",
		  ls => [ $k ] });
    return;
  }
}

1;
