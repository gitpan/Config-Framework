####################################################
## Config::Framework.pm
## Andrew N. Hicox	<andrew@hicox.com>
##
## This package provides configuration info to
## homegrown modules.
###################################################


## Global Stuff ###################################
  package Config::Framework;
  use 5.6.0;
  use Carp;

  require Exporter;
  use AutoLoader qw(AUTOLOAD);
 
## Class Global Values ############################ 
  our @ISA = qw(Exporter);
  our $VERSION = '1.04';
  our $errstr = ();
  our @EXPORT_OK = ($VERSION, $errstr);
  our @temp = split (/\//,$0);
  our %GLOB_CONFIG = (
    #name of program running this code
     'program'		=> $temp[$#temp],
    #virtual root: everything lives under this
     'v_root'			=> "<pop>v_root</pop>",
    #global configuration files live in this subdirectory
     'config_loc'		=> "<pop>config_loc</pop>",
    #sybase home directory
     'SYBASE'			=> "<pop>SYBASE</pop>",
    #oracle home directory
     'ORACLE_HOME'		=> "<pop>ORACLE_HOME</pop>",
    #set this library path
     'LD_LIBRARY_PATH'	=> "<pop>LD_LIBRARY_PATH</pop>",
    #where sendmail resides
     'sendmail'			=> "<pop>sendmail</pop>",
    #someone to phone home to when things go really wrong
     'admin'			=> "<pop>admin</pop>",
    #export these keys from GLOB_CONFIG to the shell environment
     'EnvExportList'	=> [
         "SYBASE",
         "ORACLE_HOME",
         "ORACLE_SID",
         "ARTCPPORT",
         "LD_LIBRARY_PATH"
     ],
    #we're using this encryption module
     'Crypt'			=> "<pop>Crypt</pop>",
    #it's under the virtual doormat
     'Key'				=> "<pop>Key</pop>"
 );

## new ############################################
sub new {
    #local vars
     my %p = @_;
     my ($obj) = bless (\%GLOB_CONFIG);
    #if there's anything new that needs to be exported
     if ((exists($p{EnvExportList})) && (ref ($p{EnvExportList}) eq "ARRAY")){
         foreach (@{$p{EnvExportList}}){
             push (@{$obj->{EnvExportList}}, $_);
         }
         delete ($p{EnvExportList});
     }
    #do the exports, unless EnvExportOverride is set! ;-)
     unless ($p{EnvExportOverride}){
         foreach (@{$obj->{EnvExportList}}){
             if (exists($GLOB_CONFIG{$_})){
                 $main::ENV{$_} = $GLOB_CONFIG{$_};
             }
         }
     }
    #default states
     unless (exists $p{AutoLoadUserCfg}){ $p{AutoLoadUserCfg} = 1; }
    #insert options into main object
     foreach (keys %p){ $obj->{$_} = $p{$_}; }
    #if GetSecure is set, load secure data also
     if ($obj->{GetSecure}){
         unless ($obj->LoadConfig(
             File				=> "passwds.xml",
             configNamespace	=> "Secure"
         )){
             $errstr = "Object Initialization (loading secure): $obj->{errstr}";
             return (undef);
         }
        #weed out the descriptions
         foreach (keys %{$obj->{Secure}}){ $obj->{Secure}->{$_} = $obj->{Secure}->{$_}->{content}; }
         delete ($obj->{GetSecure});
     }
    #if a file (or files) is specified, load it (them) too
     if (exists($p{File})){
         unless (ref($p{File}) eq "ARRAY"){ my $temp = $p{File}; delete ($p{File}); push (@{$p{File}},$temp); }
     }
     foreach (@{$p{File}}){
         my $data = ();
         unless ($data = $obj->LoadXMLConfig(File => $_)){
             $errstr = "Object Initialization: can't load specified config: $obj->{errstr}";
             return (undef);
         }
        #must define configNamespace
         unless ( exists ($data->{configNamespace})){
             $errstr = "Object Initialization: specified config does not define configNamespace!";
             return (undef);
         }
        #make a shortcut to the ApplicationFramework
         $data->{FrameworkDir} = "$obj->{v_root}/$obj->{config_loc}/ApplicationFrameworks/$data->{'Program Name'}";
        #stash it in the object
         $obj->{$data->{configNamespace}} = $data;
        #if defined (and ok) load userconfig
         if ((exists($data->{'User Config'})) && ($obj->{AutoLoadUserCfg})){
             unless ($obj->LoadUserCfg(
                 configNamespace	=> $data->{configNamespace}
             )){
                 $errstr = "Object Initialization (load user config): $obj->{errstr}";
                 return (undef);
             }
         }
     }
    #File option dosen't belong in the object
     delete ($obj->{File});
    #send back da object
     return ($obj);
}


## True for perl include ##########################
 1;
__END__
## AutoLoaded Methods 

## LoadXMLConfig ##################################
sub LoadXMLConfig {
    #local vars
     my $self = shift();
     my %p = @_;
    #required option
     unless (exists ($p{File})){
         $self->{errstr} = "File is a required option to LoadXMLConfig";
         return (undef);
     }
    #is there an alt location?
     if ($p{AltLoc}){
         $p{File} = "$p{AltLoc}/$p{File}";
     }else{
         $p{File} = "$self->{v_root}/$self->{config_loc}/$p{File}";
     }
    #does the specified file exist?
     if (! -e $p{File}){
         $self->{errstr} = "specified file does not exist: $p{File}";
         return (undef);
     }
    #open the file
     open (INFILE,"$p{File}") || do {
         $self->{errstr} = "can't open XML config ($p{File})! $!";
         return (undef);
     };
     my $data = join ('',<INFILE>);
     close (INFILE);
    #if it's a binary file, we'll presume it's encrypted
     if (-B $p{File}){
        #local stuff
         my ($Key,$Crypt);
        #use global Key and Crypt unless otherwise specified
         if (exists $p{Key}){ $Key = $p{Key}; }else{ $Key = $self->{Key}; }
         if (exists $p{Crypt}){ $Crypt = $p{Crypt}; }else{ $Crypt = $self->{Crypt}; }
        #get cipher, unless we have one already (and it's the same)
         unless (
             (exists($self->{Cipher})) &&
             ($Key == $self->{Key})   &&
             ($Crypt == $self->{Crypt})
         ){
             require Crypt::CBC;
             $self->{Cipher} = new Crypt::CBC($self->{Key},$self->{Crypt});
         }
        #decrypt the data
         $data = $self->{Cipher}->decrypt($data);
     }
    #get an XML parser, unless we have one already
     unless (exists($self->{XMLParser})){
        #if we've got here, than it isn't loaded yet
         require Data::DumpXML::Parser;
         $self->{XMLParser} = Data::DumpXML::Parser->new;
     }
    #parse xml
     my $info = $self->{XMLParser}->parsestring($data);
    #if there's only one element just return it
     if ($#{$info} == 0){
         return ($info->[0]);
     }else{
         return ($info);
     }
}


## LoadConfig #####################################
sub LoadConfig {
    #local vars
     my $self = shift();
     my %p = @_;
     my ($data, $namespace) = ();
    #required option
     unless (exists ($p{File})){
         $self->{errstr} = "File is a required option to LoadConfig";
         return (undef);
     }
    
    #well try it!
     unless ($data = $self->LoadXMLConfig(%p)){
         $self->{errstr} = "LoadConfig can't load specified config: $self->{errstr}";
         return (undef);
     }
    #is there a user-defined configNamespace?
     if (exists($p{configNamespace})){
         if (exists($data->{configNamespace})){
            #export under parent namespace
             $self->{$p{configNamespace}}->{$data->{configNamespace}} = $data;
             $namespace = "$p{configNamespace}/$data->{configNamespace}";
         }else{
            #export under user-defined namespace
             $self->{$p{configNamespace}} = $data;
             $namespace = $p{configNamespace};
         }
     }else{
        #no user defined configNamespace, export under own namespace, if it exists
         unless (exists($data->{configNamespace})){
             $self->{errstr} = "LoadConfig: specified config does not define configNamespace!";
             return (undef);
         }
         $self->{$data->{configNamespace}} = $data;
         $namespace = $data->{configNamespace};
     }
    #keep file in map for WriteConfig
     $self->{'_ConfigMap'}->{$namespace}->{$p{'File'}};
     return (1);
}


## WriteConfig ####################################
# store values under a given namespace to a file.
sub WriteConfig {
   #local vars
    my ($self, %p) = @_;
   #sanity chacks
    unless (exists($self->{$p{'configNamespace'}})){
        $self->{'errstr'} = "WriteConfig: specified configNamespace does not exist in this object!";
        return (undef);
    }
   #dump given namespace down to xml
    require Data::DumpXML::dump_xml;
    my $xml_data = Data::DumpXML::dump_xml($self->{$p{'configNamespace'}});
   #if no 'File' argument is given, attempt to determine the file from which this configNamespace
   #originated and use that
    unless (exists($p{'File'})){ $p{'File'} = $self->{'_ConfigMap'}->{$p{'configNamespace'}}; }
   #is there an alt location?
    if ($p{AltLoc}){
        $p{File} = "$p{AltLoc}/$p{File}";
    }else{
        $p{File} = "$self->{v_root}/$self->{config_loc}/$p{File}";
    }
   #open and dump
    open (OUTFILE, ">$p{File}") || do {
        $self->{'errstr'} = "WriteConfig: failed to open $p{File} in write mode";
        return (undef);
    };
    print OUTFILE $xml_data, "\n";
    close OUTFILE;
    return (1);
}

## LoadUserCfg ####################################
sub LoadUserCfg {
    #local vars
     my $self = shift();
     my %p = @_;
    #required option
     unless (exists $p{configNamespace}){
         $self->{errstr} = "configNamespace is a required option to LoadUserCfg";
         return (undef);
     }
    #the specified configNamespace is loaded, right?
     unless (exists $self->{$p{configNamespace}}){
         $self->{errstr} = "specified configNamespace is not loaded!";
         return (undef);
     }
    #a shortcut!
     my $data = $self->{$p{configNamespace}};
    #if defined (and ok) load userconfig
     if (exists($data->{'User Config'})){
        #do we need to copy to user's home?
         if (! -e "$ENV{HOME}/$data->{'User Config'}->{FileName}"){
            #we need a skeleton also!
             unless (-e "$data->{FrameworkDir}/$data->{'User Config'}->{'Skeleton File'}"){
                 $self->{errstr} = "User's config and skeleton file do not exist!";
                 return (undef);
             }
            #do the copy
             require File::Copy;
             unless (File::Copy::copy (
                 "$data->{FrameworkDir}/$data->{'User Config'}->{'Skeleton File'}",
                 "$ENV{HOME}/$data->{'User Config'}->{FileName}"
             )){
                 $self->{errstr} = "can't copy skeleton to user's home! $!";
                 return (undef);
             }
         }
        #well if we got here, then we're go to load it!
         unless ($self->LoadConfig(
             AltLoc			=> $ENV{HOME},
             File			=> $data->{'User Config'}->{FileName},
             configNamespace	=> $p{configNamespace}
         )){
             $self->{errstr} = "Object Initialization (userconfig): $self->{errstr}";
             return (undef);
         }
        #it MUST be all-good!
         return (1);
     }else{
        #hmm, throw an error
         $self->{errstr} = "the specified configNamespace does not define a User Config!";
         return (undef);
     }
}


## AlertAdmin #####################################
 ##todo -- add support for writing log info via Net::Syslog
sub AlertAdmin {
   #local vars
    my ($self, %p) = @_;
    my ($to) = ();
   #required option
    unless (exists ($p{Message})){
        $p{Message} = "[No Message Sent] / [System Error Message]: $!";
    }
   #if we're in debug mode, don't send email, don't log to file
    if ($self->{Debug}){
        if ($p{Die}){ die ($p{Message}, "\n"); } else { print $p{Message}, "\n"; }
        return (1);
    }
   #if additional reciepients are specified
    if (exists($p{To})){
        if (ref ($p{To}) eq "ARRAY"){
            push (@{$p{To}}, $self->{admin});
            $to = join (', ', @{$p{To}});
        }else{
            $to = "$self->{admin}, $p{To}";
        }
    }else{
        $to = $self->{admin};
    }
   #open sendmail pipe
    open (SENDMAIL, "|$self->{sendmail} -oi -t -fnobody") || do {
        #can't open sendmail! send message to v_root/var/last_resort.log
         $p{Message}=~s/\"/\\\"/g;
         my $time = time();
         system ("echo \"[$time]: CAN'T OPEN SENDMAIL! ($!) -> $p{Message}\" >> $self->{v_root}/var/log/last_resort.log");
         $self->{errstr} = "[$time]: CAN'T OPEN SENDMAIL! ($!) -> $p{Message}";
         return (undef);
    };
   #message content
    print SENDMAIL "From: nobody ($self->{program})\n";
    print SENDMAIL "To: $to\n";
    print SENDMAIL "Subject: Auto-generated Alert from: $self->{program}\n";
    print SENDMAIL "Reply-To: nobody\n";
    print SENDMAIL "Errors-To: nobody\n\n";
    print SENDMAIL "\n\n";
    print SENDMAIL $p{Message}, "\n";
    if ($p{ENV}){
        print SENDMAIL "\n[ENV] --------------------------------------------\n";
        foreach (keys %ENV){ print SENDMAIL "[$_]: $ENV{$_}\n"; }
    }
    close (SENDMAIL);
   #log to file 
    if ($p{Log}){ $self->Log(%p); }
    if ($p{Die}){ die ($p{Message}, "\n"); }
    return (1);
}


## Log ############################################
sub Log {
    my ($self, %p) = @_;
   #required options
    unless ((exists($p{Message})) && (exists($p{Log}))){
        $self->{errstr} = "Message and Log are required options";
        return (undef);
    }
   #make sure the logfile exists
    unless (-e "$self->{v_root}/$p{Log}"){
         $self->{errstr} = "specified logfile does not exist!";
         return(undef);
    }
   #do the dam thang ##ghetto until we get the syslog thing worked out
    my $time = time();
    if ($self->{'AsymetricLogging'}){ $p{Log} .= " &"; }
    system("echo \"[$time]: $p{Message}\" >> $self->{v_root}/$p{Log}");
    if ($p{Echo}){ carp $p{Message}; }
    return(1);
}
