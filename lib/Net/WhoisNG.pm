package Net::WhoisNG;

#use 5.008004;
use strict;
use warnings;
use Carp;
use IO::Socket;
use IO::File;
use Net::WhoisNG::Person;
#use AutoLoader 'AUTOLOAD';

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Net::WhoisNG ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.05';

sub new{
   my $class=shift;
   my $self={};
   my $domain=shift;
   my $tld;
   my $drop;
   $domain=~ s/\s+//g;
   $domain=~ s/\n+//g;
   
   ($drop,$tld)=split(/\./,$domain);
   $self->{domain}=$domain;
   #now we try to connect to repective tld serverl
   my $server="$tld.whois-servers.net";
   $self->{server}=$server;
   bless $self;
   return $self;
}

sub getConnection{
   my $self=shift;
   return $self->{socket};
}

sub lookUp{
   my $self=shift;
   my $raw_domain;
   my $domain;
   my $server=$self->{server};
   if($self->{domain}){
      $raw_domain=$self->{domain};
   }   
   my $ip = gethostbyname($server) or die "Failed gethostbyname $server\n";
   $ip = inet_ntoa($ip);
   my $sock = IO::Socket::INET->new(PeerAddr => $ip, PeerPort => 'whois', Proto => 'tcp') or print "Socket to $ip failed on $raw_domain\n" and return 0;
   $sock->autoflush();
   if($sock){
      $self->{socket}=$sock;
   }else{
      print "Bad Socket. Exiting ...\n";
      exit;
   }

   $domain=$self->fixFormat($raw_domain);
   print $sock uc("$domain\n");
   my @rslts=<$sock>;
   if($domain=~ /com$/ or $domain=~ /.net$/){
      for(my $n=0;$n<@rslts;$n++){
         if($rslts[$n]=~ /Whois Server:\s+(\S+)\s+/){
            $server=$1;
            $sock->close();
            $ip = gethostbyname($server) or die "Failed gethostbyname\n";
            $ip = inet_ntoa($ip);
            $sock = IO::Socket::INET->new(PeerAddr => $ip, PeerPort => 'whois', Proto => 'tcp',Timeout => "5",) or print "Socket failed on $raw_domain\n" and return 0;
            $sock->autoflush();
            print $sock uc("$raw_domain\n");
            @rslts=<$sock>;
            
            $sock->close();
           # exit;
         }
      }
   }
   $self->{rslts}=\@rslts;
   my $rst=$self->parseResult();
   return $rst;
   #print @rslts;
}


sub fixFormat{
   my $self=shift;
   my $domain=shift;
   my ($drop,$tld)=split(/\./,$domain);
   if($tld=~ /com/i){
      return "domain $domain";
   }
   else{
      return $domain;
   }
}

sub parseResult{
   my $self=shift;
   my $rslt_ref=$self->{rslts};
   my @rslts=@$rslt_ref;
   my $capadmin=0;
   my $captech=0;
   my $capns=0;
   my $cappin=0;
   my $capregistrant;
   my $offset;
   my @tcap;
   $self->{nameservers}=undef;
   
   foreach my $line(@rslts){
      $line=~ s/\t/        /g;
      if($self->{domain}=~ /.com$/ or $self->{domain}=~ /.net$/){
         if($line=~ /No Match/i){
            return 0;
         }
         #Do com and .net specific parsing
         if($line=~ /Registrar:\s+((\S+)\s+)+/g){
            $self->setRegistrar($2);
           # print "got $2\n";
         }
         if($line=~ /Registrar\s+Name:\s+((\S+)\s+)+/g){
            $self->setRegistrar($2);
            next;
         }
         my $raw_date;
         if($line=~ /created on\s+(\S+)./ or $line=~ /Created on\S*:\s+(\S+)\s+$/i or $line=~ /Created on\S+:\s+((\S+\s+)+)/){
            $raw_date=$1;
            $self->setCreatedDate($self->sanitizeDate("$raw_date"));
            next;
         }
         if($line=~ /Expires on\s+(\S+)./gi or $line=~ /expires on\S*:\s+(\S+)\s+$/i  or $line=~ /expires on\S+:\s+((\S+\s+)+)/gi){
            $raw_date=$1;
            #print "Date is $raw_date\n";            
            $self->setExpirationDate($self->sanitizeDate("$raw_date"));
         }
         if($line=~ /updated on\s+(\S+)\./i or $line=~ /updated on\S*:\s+(\S+)\s+$/i or $line=~ /updated on\S+:\s+((\S+\s+)+)/i){
            $raw_date=$1;
            $self->setLastUpdated($self->sanitizeDate("$raw_date"));
         }
         if($capadmin or $captech or $capregistrant){
               my $toffset=0;
            if($line=~ /(\s+)\S+/){
               $toffset=length($1);
              # print "toffset is $toffset\n";
            }
            elsif($line=~ /^\s+$/){
               $toffset=-1;
            }
            if($toffset>$offset){
               chomp $line;
               push(@tcap,$line);
            }
            else{
               #done Capturing
               if($capadmin){
                  #create new object for admin person
                  my $admin=new Net::WhoisNG::Person();
                  my @cap=@tcap;
                  $admin->{credentials}=\@cap;
                  $self->addPerson($admin,"admin");
               }
               if($captech){
                  #create tech person object if it doesnt exist
                  my @cap=@tcap;
                  my $tech=new Net::WhoisNG::Person();
                  $tech->{credentials}=\@cap;
                  $self->addPerson($tech,"tech");
               }
               undef @tcap;
               $captech=0;
               $capadmin=0;
               $capregistrant=0;
            }
         }
         elsif($capns){
            if($line=~ /(\S+)/){
               $cappin=1;
               push(@tcap,$line);
               if($rslts[$#rslts]=~ /$1/){
                  #done capturing. 
                  my @cap=@tcap;
                  $self->{nameservers}=\@cap;
                  $capns=0;
                  $cappin=0;
                  undef @tcap;
               }
               next;
            }
            if($cappin and ($line=~ /^\s+$/ )){
               #done capturing
               my @cap=@tcap;
               $self->{nameservers}=\@cap;
               $capns=0;
               $cappin=0;
               undef @tcap;
               next;
            }
         }
         if($line=~ /Domain\s+servers/i or $line=~ /name\s+servers/i){
            $capns=1;
            next;
         }
         if($line=~ /(\s*)Administrative\s+Contact:/ or $line=~ /(\s*)Administrative\s+Contact(\S+\s+)(\S+)/){
            $capadmin=1;
            if(defined($3)){
               if($3=~ /techn/i){
                  $captech=1;
               }
            }
            $offset=length($1);
            #print "My offset is ",$offset,"\n";
            next;
         }
         if($line=~/(\s*)Technical\s+Cont/i){
            $captech=1;
            if($self->getPerson("tech")){
               $captech=0;
               next;
            }
            $offset=length($1);
            #print "My offset is ",length($offset),"\n";
            next;
         }
      }
      elsif($self->{domain}=~ /.edu/){
         if($line=~ /^No Match/){
         return 0;
         }
         my $raw_date;
         if($line=~ /activated:\s+(\S+)\s+$/i){
            $raw_date=$1;
            $self->setCreatedDate($self->sanitizeDate("$raw_date"));
            next;
         }
         if($line=~ /updated:\s+(\S+)\s+$/i){
            $raw_date=$1;
            $self->setLastUpdated($self->sanitizeDate("$raw_date"));
         }
         if($capadmin or $captech or $capregistrant){
            my $toffset;
            my $cont=0;
            if($line=~ /^\s+$/){
            #print "Current tcap size:",@tcap+0;;
               if(!@tcap){
               #print "Unnecessary space\n";
                     next;
                  }
                  else{
                     $cont=1;
                  }
            }
            else{
               #capture lines
               chomp $line;
               push(@tcap,$line);
               next;               
            }
               #done Capturing
               if($capadmin){
                  #create new object for admin person
                  if(@tcap<1){
                     next;
                  }                  
                  my $admin=new Net::WhoisNG::Person();
                  my @cap=@tcap;
                  $admin->{credentials}=\@cap;
                  $self->addPerson($admin,"admin");
               }
               if($captech){
                  if(@tcap<1){
                     next;
                  }
                  my @cap=@tcap;
                  my $tech=new Net::WhoisNG::Person();
                  $tech->{credentials}=\@cap;
                  $self->addPerson($tech,"tech");
               }
               undef @tcap;
               $captech=0;
               $capadmin=0;
               $capregistrant=0;
            }
         
         elsif($capns){
            if($line=~ /(\S+)/){
               $cappin=1;
               push(@tcap,$line);
               if($rslts[$#rslts]=~ /$1/){
                  #done capturing. 
                  my @cap=@tcap;
                  $self->{nameservers}=\@cap;
                  $capns=0;
                  $cappin=0;
                  undef @tcap;
               }
               next;
            }
            if($cappin and ($line=~ /^\s+$/ )){
               #done capturing
               my @cap=@tcap;
               $self->{nameservers}=\@cap;
               $capns=0;
               $cappin=0;
               undef @tcap;
               next;
            }
         }
         if($line=~ /name\s+servers:/i){
            $capns=1;
            next;
         }
         if($line=~ /(\s*)Administrative\s+Contact:/){
            $capadmin=1;
            undef @tcap;
            next;
         }
         if($line=~/(\s*)Technical\s+Cont/i){
            $captech=1;
            undef @tcap;
            next;
         }
      }
      elsif($self->{domain}=~ /.org/ or $self->{domain}=~ /.info/) {
         # Above extensions are the most code friendly
         #Registrant Street1:Whareroa Rd
         if($line=~ /NOT\s+FOUND/){
            return 0;
         }
         if($line=~ /^Billing/ or $line=~ /^Admin/ or $line=~ /^Tech/ or $line=~ /^Registrant/){
            $line=~ /(\S+)(\s+\S+){1,2}:((\S+\s+)+)/;
            #check if person object exists and get handle
            my $key=$1;
            my $prop="none";
            if($2){
               $prop=$2;
            }
            my $val;
            if($3){
             $val=$3;
            chomp $val;
            }
            $key=lc($key);
            my $person;
            if($self->getPerson($key)){
               $person=$self->getPerson($key);
            }
            else{
               $person=new Net::WhoisNG::Person();
               $self->addPerson($person,$key);
            }
            if($prop=~ /ID:/i){
               $person->setID($val);
               next;
            }
            elsif($prop=~ /name/i){
               $person->setName($val);
               next;
            }
            elsif($prop=~ /organization/i){
               $person->setOrganization($val);
            }
            elsif($prop=~ /street1/i){
               $person->setStreet($val);
               next;
            }
            elsif($prop=~ /street2/i){
               $val=$person->getStreet()."\n$val";
               $person->setStreet($val);
               next;
            }
            elsif($prop=~ /city/i){
               $person->setCity($val);
               next;
            }
            elsif($prop=~ /code/i){
               $person->setPostalCode($val);
               next;
            }
            elsif($prop=~ /country/i){
               $person->setCountry($val);
               next;
            }
            elsif($prop=~ /phone/i){
               $person->setPhone($val);
               next;
            }
            elsif($prop=~ /email/i){
               $person->setEmail($val);
               next;
            }
         }
         elsif($line=~ /name\s+server:(\S+\s+)/i){
            $self->addNameServer($1);
         }
         elsif($line=~ /expiration\s+date:(\S+)/i){
            $self->setExpirationDate($self->sanitizeDate($1));
         }
         elsif($line=~ /last\s+updated:(\S+)/i){
            $self->setLastUpdated($self->sanitizeDate($1));
         }
      }
      # Will implement .biz here
      elsif($self->{domain}=~ /.biz/) {
         # Above extensions are the most code friendly
         #Registrant Street1:Whareroa Rd
         if($line=~ /NOT\s+FOUND/i){
            return 0;
         }
         if($line=~ /^Billing/ or $line=~ /^Admin/ or $line=~ /^Tech/ or $line=~ /^Registrant/){
            $line=~ s/Contact//;
            $line=~ /(\S+)(\s+\S+){1,2}:\s+((\S+\s+)+)/;
            #check if person object exists and get handle
            my $key=$1;
            my $prop=$2;
            my $val=$3;
            chomp $val;
            $key=~ s/ing//;
            $key=~ s/nical//;
            $key=~ s/istrative//;
            $key=lc($key);
            my $person;
            if($self->getPerson($key)){
               $person=$self->getPerson($key);
            }
            else{
               $person=new Net::WhoisNG::Person();
               $self->addPerson($person,$key);
            }
            if($prop=~ /ID:/){
               $person->setID($val);
               next;
            }
            elsif($prop=~ /name/i){
               $person->setName($val);
               next;
            }
            elsif($prop=~ /organization/i){
               $person->setOrganization($val);
            }
            elsif($prop=~ /address1/i){
               $person->setStreet($val);
               next;
            }
            elsif($prop=~ /address2/i){
               $val=$person->getStreet()."\n$val";
               $person->setStreet($val);
               next;
            }
            elsif($prop=~ /city/i){
               $person->setCity($val);
               next;
            }
            elsif($line=~ /postal\s+code/i){
               $person->setPostalCode($val);
               next;
            }
            elsif($prop=~ /country/i){
               $person->setCountry($val);
               next;
            }
            elsif($line=~ /phone\s+number/i){
               $person->setPhone($val);
               next;
            }
            elsif($prop=~ /email/i){
               $person->setEmail($val);
               next;
            }
         }
         elsif($line=~ /name\s+server:\s+(\S+\s+)/i){
            $self->addNameServer($1);
         }
         #Tue Oct 28 16:05:56 GMT+00:00 2003
         elsif($line=~ /expiration\s+date:\s+((\S+\s+)+){1,6}/i){
            $self->setExpirationDate($self->sanitizeDate($1));
         }
         elsif($line=~ /last\s+updated\s+date:\s+((\S+\s+)+){1,6}/i){
            $self->setLastUpdated($self->sanitizeDate($1));
         }
      }
      else{
         print "Parsing for $self->{domain} TLD not yet implemented\n";
         return 0;
      }
   }
   return 1;
}

sub sanitizeDate{
   # we need to set a consistent date output format. We want something we can manipulate. mmm-dd-yyyy
   # Tue, Apr 17, 2001
   my $self=shift;
   my $raw_date=shift;
   #print "Raw date recieved: $raw_date\n";
   if($raw_date=~ /(\d{1,2})-(\w\w\w)-(\d\d\d\d)/){
      return "$2-$1-$3";
   }
   elsif($raw_date=~ /(\d\d\d\d)-(\w\w\w)-(\d\d$)/){
      return "$2-$3-$1";
   }
   elsif($raw_date=~ /(\d\d\d\d)-(\w\w\w)-(\d\d).$/){
      return "$2-$3-$1";
   }
   elsif($raw_date=~ /\w\w\w,\s+(\S+)\s+(\d{1,2}),\s+(\d\d\d\d)/){
      return "$1-$2-$3";
   }
   elsif($raw_date=~ /(\d{1,2})-(\w\w\w)-(\d\d)/){
      return "$2-$1-20$3";
   }
   elsif($raw_date=~ /((\S+\s+)+){1,6}/){
      my @tmp=split(/\s+/,$raw_date);
      return $tmp[1]."-".$tmp[2]."-".$tmp[5];
   }
}

sub getLastUpdated{
   my $self=shift;
   return $self->{lastupdated};
}

sub setLastUpdated{
   my $self=shift;
   $self->{lastupdated}=shift;
}

sub getDomainName{
   my $self=shift;
   return $self->{domain};
}

sub getSponsor{
}

sub setSponsor{
}

sub getRegistrar{
   my $self=shift;
   return $self->{registrar};
}

sub setRegistrar{
   my $self=shift;
   $self->{registrar}=shift;
}

sub getExpirationDate{
   my $self=shift;
   return $self->{expirationdate};
}

sub setExpirationDate{
   my $self=shift;
   $self->{expirationdate}=shift;
}

sub setCreatedDate{
   my $self=shift;
   $self->{createddate}=shift;
}

sub getCreatedDate{
   my $self=shift;
   return $self->{createddate};
}

sub getStatus{
   my $self=shift;
   if(defined($self->{status})){
      return $self->{status};
   }
   my %months=(jan=>1, feb=>2, mar=>3, apr=>4, may=>5, jun=>6, jul=>7, aug=>8, sep=>9, oct=>10, nov=>11, dec=>12);
   my $exp=$self->getExpirationDate();
   return 0 unless defined($exp);
   my ($emonth,$eday,$eyear)=split(/-/,$exp);
   $emonth=$months{lc($emonth)};
   if(length($emonth)==1){
      $emonth="0$emonth";
   }
   $exp=$eyear.$emonth.$eday;
   my @now=localtime();
   my $cyear=$now[5];
   $cyear=$cyear+1900;
   my $cmonth=$now[4];
   if(length($cmonth)==1){
      $cmonth="0$cmonth";
   }   
   my $cday=$now[3];
   if(length($cday)==1){
      $cday="0$cday";
   }
   my $cur=$cyear.$cmonth.$cday;
  my $status=$exp-$cur;
  if($status>=0){
     return 1;
  }
  return 0;
}

sub setStatus{
}

sub getPerson{
   my $self=shift;
   my $type=shift;
   my $t_people=$self->{people};
   my %people;
   if(defined($t_people)){
      %people=%$t_people;
      return $people{$type};
     }
     return undef;
}

sub addPerson{
   my $self=shift;
   my $person=shift;
   my $type=shift;
   #print "Adding $type #####\n";
   my %people;
   if($self->{people}){
      my $t_people=$self->{people};
      %people=%$t_people;
   }
   $people{$type}=$person;
   $self->{people}=\%people;
}

sub addNameServer{
   my $self=shift;
   my $svr=shift;
   #chomp $svr;
   $svr=~ s/\r\n//g;
   $svr=~ s/\n//g;
   $svr=~ s/\r//g;
   my @ns;
   if(defined($self->{nameservers})){
      my $t_ns=$self->{nameservers};
      @ns=@$t_ns;
   }
   push(@ns,$svr);
   $self->{nameservers}=\@ns;
}

sub getNameServers{
   my $self=shift;
   return $self->{nameservers};
}

sub expired{
}

sub lookup{
   my $self=shift;
   return $self->lookUp();
}
# Preloaded methods go here.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::WhoisNG - Perl extension for whois  and parsing

=head1 SYNOPSIS

  use Net::WhoisNG;
  my $w=new Net::WhoisNG($domain);
  if(!$w->lookUp()){
     print "Domain not Found\n";
     exit;
  }
  # If lookup is successful, record is parsed and ready for use
  
=head2 Methods 
 
   Single Value properties return respective scalars from their getXX methods.
   The available single value getXX method are getExpirationDate(), getLastUpdated(),
   getCreatedDate(), getStatus(). 
   
   my $exp_date=$w->getExpirationDate();
   
   Obtaining name servers is done with getNameServers() which returns a reference to an
   array of name servers.
   
   my $t_ns=$w->getNameServers();
   my @ns=@$t_ns;
   
   Contacts are implemeted as a person object.
   
   my $contact=$w->getPerson($type);
   
   'type' is one of (admin,tech,registrant,bill)
   
   The Person Object implements several methods to obtain properties of the contact
   
   $contact->getCredentials(); #Returns a ref to an array of contact info for $type
   
   getCredentials() was implemeted to return an unparsed set of info about a contact beacause some 
   whois servers are so irregular in their formatting that it was a impractical to 
   parse the contact info further. Where available such as with .org and .info the following methods work.
   
   getName(), getOrganization(), getState(), getPostalCode, getCountry(), getEmail(),
   getStreet(), getPhone(), getFax()
   
=head1 DESCRIPTION

Whois Next Generation. Whois lookup module alternative to Net::Whois 

This module is used to lookup whois information on domains. I decided to 're-invent' the wheel because the Net::Whois only
supports .org and .info formats and did not implement expiration date as of june 2004. 

This version supports the com, net, org, info, biz and edu TLDs. Rapidly implementing other TLDs.

The module starts by examinig the extension and setting the appropriate whois server. The whois server URL is constructed as $tld.whois-servers.net. The method lookUp() then tries to connect and query the server. It then hands over to a parser and 
returns 1 if successful or 0 otherwise. U can then obtain various properties using methods listed above. Note that not all properties will be defined for every domain.  

=head2 EXPORT

None.



=head1 SEE ALSO

Net::WhoisNG::Person, whois

http://www.freebsdadmin.net

=head1 AUTHOR

Pritchard Musonda, E<lt>stiqs@blackhills.net<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Pritchard Musonda

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
