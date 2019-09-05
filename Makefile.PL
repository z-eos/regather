# -*- cperl -*-
use strict;
use warnings;
use ExtUtils::MakeMaker;
use Module::Metadata;

WriteMakefile(NAME             => 'regather',
              ABSTRACT_FROM    => 'regather',
              VERSION_FROM     => 'regather',
	      EXE_FILES        => [ 'regather' ],
              AUTHOR           => 'Zeus Panchenko <zeus@gnu.org.ua>',
              LICENSE          => 'gpl_3',
              MIN_PERL_VERSION => 5.016001,
              PREREQ_PM        => {
				   'Data::Printer'        => '0.40',
				   'File::Temp'           => '0.22',
				   'Text::Locus'          => '1.01',
				   'Config::AST'          => '1.05',
				   'Config::Parser'       => '1.04',
				   'Config::Parser::ldap' => '1.00',
				   'Net::LDAP'            => '0.65',
				   'Template::Toolkit'    => '2.29',
				   'Sys::Syslog'          => '0.35'
				  },
              META_MERGE      =>
	      {
	       'meta-spec' => { version => 2 },
	       resources   => {
			       repository => {
					      type => 'git',
					      url => 'ssh://git@github.com:z-eos/regather.git',
					      web => 'https://github.com/z-eos/regather.git',
					     },
			      },
	      }
	     );
