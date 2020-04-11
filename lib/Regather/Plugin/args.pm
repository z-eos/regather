# -*- mode: cperl; mode: follow; -*-
#

package Regather::Plugin::args;

=head1 NAME

args - stub plugin, just prints its arguments

=cut

use strict;
use warnings;
use Regather::Logg;

=head1 METHODS

Each loadable module must provide at least two method: the
cosntructor B<new> and runtime method B<run>.

=head2 new

Creates an instance of the class and saves a reference to its
arguments for further use.

=cut

sub new {
    my $class = shift;
    bless { args => shift }, $class;
}

=head2 run

Displays the full package name and arguments it's been called with.

=cut

sub run {
  my $self = shift;

  $self->{args}->{log}->cc( pr => 'debug',
			    fm => "%s called with arguments: %s",
			    ls => [ __PACKAGE__,
				    join(',', @{$self->{args}->{params}}), ] );
}

1;
