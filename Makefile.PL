# $Id: Makefile.PL,v 1.6 2006/08/04 20:09:23 ajk Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    ABSTRACT_FROM  => 'lib/Data/Passphrase.pm',
    AUTHOR         => 'Andrew J. Korty <ajk@iu.edu>',
    EXE_FILES      => [qw(scripts/passphrase-test)],
    NAME           => 'Data::Passphrase',
    PREREQ_PM      => {
        Object::InsideOut => 1.33,
        Readonly          => 1.03,
        Test::More        => 0.54,
        version           => 0.53,
    },
    SIGN           => 1,
    VERSION_FROM   => 'lib/Data/Passphrase.pm',
);
