# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-WhoisNG.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 2;
BEGIN { use_ok('Net::WhoisNG') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.


my $dom="freebsd.org";
my $w = new Net::WhoisNG("freebsd.org") or die "domain creation failed\n";
if(!$w->lookUp()){
   print "Domain not found\n";
   exit;
}
#my $test=$w->getRegistrar();
#print "registrar: $test\n";
my $t2=$w->getNameServers();
print "Heres the NAMESERVERS\n",@$t2;
my $ex=$w->getExpirationDate();
print "Expires: $ex\n";
my $p=$w->getPerson("tech") or die "No admin contact\n";
my $tc=$p->getCredentials();
my @c=@$tc;
print STDOUT "Tech Contact:\n",join("\n",@c);
my $status=$w->getStatus();

if($status){
   print "Domain is Active\n";
}
else{
   diag "Domain expire: $ex\n";
}
ok(1);