#use 5.008004;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::WhoisNG',
    VERSION_FROM      => 'lib/Net/WhoisNG.pm', # finds $VERSION
    PREREQ_PM         => {Net::WhoisNG::Person =>0.02}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/WhoisNG.pm', # retrieve abstract from module
       AUTHOR         => 'Pritchard Musonda <stiqs@blackhills.net>') : ()),
);
 
