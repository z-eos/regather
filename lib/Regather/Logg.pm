# -*- mode: cperl; mode: follow; -*-
#

package Regather::Logg;

use strict;
use warnings;
use diagnostics;
use Sys::Syslog qw(:standard :macros);
use Data::Printer caller_info => 1, class => { expand => 2 };

# https://upload.wikimedia.org/wikipedia/commons/1/15/Xterm_256color_chart.svg
use constant dpc => { info    => 'ansi113',
		      err     => 'bold ansi255 on_ansi196',
		      debug   => 'ansi195', #grey18', #bright_yellow',
		      warning => 'bold ansi237 on_ansi214', #bright_yellow',
		    };

sub new {
  my $class           = shift;
  local %_            = @_;
  my $self            = bless {}, $class;
  $self->{prognam}    = $_{prognam};
  $self->{foreground} = $_{foreground} // 0;
  $self->{colors}     = $_{colors}     // 0;
  $self->{ts_fmt}     = "%a %F %T %Z (%z)";

  openlog($self->{prognam}, "ndelay,pid") if ! $self->{foreground};

  $self
}

sub conclude {
  my ( $self, %args ) = @_;
  my %arg = ( fg => $args{fg} // $self->{foreground},
	      pr => $args{pr} // 'info',
	      fm => $args{fm}, );
  $arg{pr_s} = sprintf("%s|%s", $arg{pr}, $self->{facility} // 'local4');
  $arg{pr_f} = sprintf("%s: ", uc($arg{pr}) );

  if ( exists $args{ls} ) {
    @{$arg{ls}} = map { ref && ref ne 'SCALAR' ? np($_, caller_info => 0) : $_ } @{$args{ls}};
  } else {
    $arg{ls} = [];
  }

  if ( $arg{fg} ) {
    $arg{msg} = sprintf $arg{pr_f} . $arg{fm}, @{$arg{ls}};
    p($arg{msg},
      colored     => $self->{colors} && $self->{foreground},
      caller_info => 0,
      color       => { string => dpc->{$arg{pr}}},
      output      => 'stdout' );
  } else {
    syslog( $arg{pr_s}, $arg{pr_f} . $arg{fm}, @{$arg{ls}} );
  }
}

sub cc { goto &conclude }

sub conclude_ldap_err {
  my ( $self, %args ) = @_;
  $self->cc( pr => 'err', fm => "LDAP ERROR:\n% 13s%s\n% 13s%s\n% 13s%s\n% 13s%s\n\n",
	     ls => [ 'ERROR: ',        $args{mesg}->error_name,
		     'TEXT: ',         $args{mesg}->error_text,
		     'DESCRIPTION: ',  $args{mesg}->error_desc,
		     'SERVER ERROR: ', $args{mesg}->server_error ] );
}

sub cc_ldap_err { goto &conclude_ldap_err }

sub set_m {
  my ( $self, $cf ) = @_;
  if ( ref($cf) eq 'HASH' ) {
    while ( my ( $k, $v ) = each %$cf ) {
      next if exists $self->{$k};
      $self->{$k} = $v;
    }
  } else {
    $self->cc( pr => 'err',
	       fm => "Logg::set_m(): argument supplied is not HASH ..." );
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
    $self->cc( pr => 'err',
	       fm => "attribute \"%s\" doesn't exist",
	       ls => [ $k ] );
    return;
  }
}

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Regather::Logg - logging class

=head1 SYNOPSIS

    use Regather::Logg;
    my $log = new Regather::Logg( prognam    => 'MyAppName',
			          foreground => $foreground_or_syslog,
			          colors     => $wheather_to_use_term_colors );
    $log->cc( pr => 'info', fm => "Regather::Logg initialized ... (write to syslog)" );
    $log->cc( fg => 1, fm => "Regather::Logg initialized ... (write to STDOUT)" );
    ...
    my $mesg = $ldap->search( filter => "(objectClass=unsearchebleThing)");
    $log->logg_ldap_err( mesg => $mesg );

=head1 DESCRIPTION

This is a class to log messages.

=head1 CONSTRUCTOR

=over 4

=item new

Creates a new B<Regather::Logg> object

=over 4

=item prognam =E<gt> 'MyAppName'

program name

=item foreground =E<gt> 1 | 0

STDOUT or syslog, default is: 0

=item colors =E<gt> 1 | 0

wheather to use terminal colors, default is: 0

if set, then priorities are colored this way:

=over 4

info    => 'ansi113'

err     => 'bold ansi255 on_ansi196'

debug   => 'ansi195'

warning => 'bold ansi237 on_ansi214'

=back

for reference look at L<Term::ANSIColor>

=item ts_fmt =E<gt> 'strftime(3) format string'

timestamp format string, default is: "%a %F %T %Z (%z)"

=back

=back

=head1 METHODS

=over 4

=item logg

main method to do the job

=over 4

=item fg =E<gt> 1 | 0

foreground: stdin or syslog

=item pr =E<gt> 'level[|facility]'

priority

=item fm =E<gt> "... %s ... : %m"

sprintf format string, with the addition that %m is replaced with "$!"

=item ls =E<gt> [ $a, $b, ... ]

list of values to be passed to sprintf as arguments

=back

=item logg_ldap_err

method - wrapper around Net::LDAP::Message->error methods

=over 4

=item mesg =E<gt> Net::LDAP::Message object

wrapper to log to syslog or stdin. On input it expects hash

=back

=item set

setter to set one single pair key => value

=over 4

=item key =E<gt> value

=back

=item set_m

setter to set options from config file

on input it expects Regather::Config object section for Regather::Logg

=item get

getter

=back

=head1 SEE ALSO

L<Sys::Syslog>,
L<Data::Printer>,
L<Term::ANSIColor>

=head1 AUTHOR

Zeus Panchenko E<lt>zeus@gnu.org.uaE<gt>

=head1 COPYRIGHT

Copyright 2019 Zeus Panchenko.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

=cut

