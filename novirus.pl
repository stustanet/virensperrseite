#!/usr/bin/perl
#
# This file originated from blockpage.pl.
# It's purpose is to show either a blockpage if the requesting IP is blocked
# or a "everything's fine" page if the user is NOT blocked.
# it should be accessible via "novirus.stusta.de" and the proxy should redirect
# to it instead of showing "127.0.0.1:81".
#
# blockpage.pl annotated by suhu <stefan.huber@stusta.de> on 2016-10-22
# novirus.pl copied from blockpage.pl on 2016-10-22
# novirus.pl extended by suhu <stefan.huber@stusta.de> on 2016-10-22
#
# Wolfgang Walter meinte "FM steht für FehlerMeldung, dass man leichter grepen
#                         kann"

use strict;
use warnings;

use IO::File;
use FCGI;
use Linux::Inotify2;
use File::Slurp;
use File::Basename;
use NetAddr::IP;
use NetAddr::IP::Util;
use Encode;

# array of block types, that means either dynamic or permanent
my @blocktypes = ( 'dynamic', 'permanent', 'noblock' );

# array of filetypes
# apparently this script can load a blocklist and html templates
my @filetypes = ( 'blocklist', 'error_page_template' );

# standard path. here the list of blocked ips should be.
my $incoming = '/home/scp-rec/incoming';

# hashmap for the block page templates, access with
# $templates{'dynamic'} or $templates{'permanent'}
my %templates;

# hashmap of blocked accounts:
# access: $blocklists{'dynamic'}{"10.150.51.80"} = "awesome guy"
my %blocklists;

# hash
my %readconfig;

my $stats;
my $updates = 0;

my $handling_request = 0;
my $exit_requested = 0;

my $notifier;
my $request;
my $isfcgi;

# apparently this scrip is to be run in background and can get unix
# handler requests
sub sig_handler_exit {
	$exit_requested = 1;
	$handling_request or exit(0);
}

$SIG{USR1} = \&sig_handler_exit;
$SIG{TERM} = \&sig_handler_exit;
$SIG{PIPE} = sub { die 'SIGPIPE\n'; };

# this subroutine loads both error page templates into the templates hashmap
sub load_error_page_template {
	my ($blocktype, $filepath) = (@_);

	my $content;
	eval {
		$content = File::Slurp::read_file($filepath, binmode => ':utf8');
	};
	if ($@) {
		print STDERR "FM $@";
		return;
	}
	$templates{$blocktype} = $content;
}

# load_blocklist
# @param blocktype Which blocktype should be loaded ('dynamic' or 'permanent'
# @param filepath filepath to the blocklist, e.g. $incoming (see above)
sub load_blocklist {
	my ($blocktype, $filepath) = (@_);

	# %block is a hashmap of blocked accounts: ip -> reason
	# e.g. $block{'10.150.51.80'} = 'awesome guy'
	# access: $blocklists{'dynamic'}{'10.150.51.80'} = 'awesome guy'
	my %block;

	#print STDERR "load_blocklist: $blocktype, $filepath\n";
	eval {
		# fh = FileHandler for the blocklist file
		my $fh = IO::File->new($filepath) or die "can't read $filepath: $!\n ";
		while (defined(my $line = <$fh>)) {
			$line =~ /^#/ and next; # ignore lines starting with #
			# regex: \s is whitespace character
			my ($ip, $reason) = split(/\s+#\s+/, $line, 2);
			defined($ip) or next; # if the split didn't return an
                                              # ip -> next
			defined($reason) or $reason = "Virus/Trojaner/Stoerer";
			# substitute chars '&', '<' and '>' with HTML code
			$reason =~ s/\&/\&amp;/g;
			$reason =~ s/\</\&lt;/g;
			$reason =~ s/\>/\&gt;/g;
			# make an IP object from the string
			$ip = NetAddr::IP->new($ip);
			defined($ip) or next; # when it was no correct IP -> next
			for (my $i=$ip->network, my $j=0;; $i++, $j++) {
				$block{$i->addr} = $reason;
				$i == $i->broadcast and last;
				if ($j >= 255) {
					# nicht mehr als maximal 256
					print STDERR "WARNING: subnet $ip has more than 256 addresses; ignoring\n";
					last;
				}
			}
		}
		# on read error: die!
		$fh->error and die "error when read $filepath: $!\n ";
		$block{error} = "Virus/Trojaner/Stoerer";
	};
	# $@ = Error Message fom the last eval command.
	if ($@) {
		print STDERR "$@";
		return;
	}
	#print STDERR "load_blocklist: loaded $blocktype, $filepath\n";
	$blocklists{$blocktype} = \%block;
}

sub watch_callback {
	my $ev = shift;
	my $filepath = $ev->fullname;
	$readconfig{$filepath} = 1;
	#print STDERR "DM $filepath\n";
}

sub check_config {
	$notifier->poll();
	foreach my $filepath (grep( { $readconfig{$_} } keys(%readconfig))) {
		my $filename = File::Basename::basename($filepath);
		my ($filetype, $blocktype) = split(/-/, $filename, 2);
		#print STDERR "DM check_config $filepath\n";
		if ($filetype eq 'blocklist') {
			load_blocklist($blocktype, $filepath);
		} elsif ($filetype eq 'error_page_template') {
			load_error_page_template($blocktype, $filepath);
		}
		$readconfig{$filepath} = 0;
	}
}

# do_errorpage prints an HTML error page if called.
# should thus be called when unrecoverable error occurs.
# in production environment: should not ever be executed!
sub do_errorpage {
	print(	"Status: 404\r\n",
		"Content-type: text/plain\r\n\r\n")
	or $isfcgi or die "FM error when writing to stdout: $!\n ";
	if (0) {
	print "hallo\r\n";
	my $pathinfo = $ENV{PATH_INFO};
	$pathinfo or $pathinfo = '';
	my $scriptname = $ENV{SCRIPT_NAME};
	$scriptname or $scriptname = '';
	print "PATH_INFO=$pathinfo\r\nSCRIPT_NAME=$scriptname\r\n";
	}
}

# this is pretty much the main routine
sub do_request() {
# determine ip-address
	my $clientip = $ENV{REMOTE_ADDR};
	if (! defined($clientip)) {
		do_errorpage();
		return;
	}

# determine block reason and blocktype
	my $ip = NetAddr::IP->new($clientip);
	defined($ip) and $clientip = $ip->addr;
	my $reason;
	my $blocktype;
	# hint: @blocktypes = {'permanent', 'dynamic', 'noblock'}
	foreach my $b (@blocktypes) {
		if ($blocklists{$b} && ($reason = $blocklists{$b}->{$arg1})) {
			$blocktype = $b;
			last;
		}
	}

	if (! defined($blocktype)) {
		$blocktype = $blocktypes[2];
		$reason = "because you are awesome!"
	}

	if (! defined($reason)) {
		$blocktype = $blocktypes[0];
		$reason = $blocklists{$blocktype}->{error};
	}

# load and modify the blockpage template
	my $template = $templates{$blocktype};

	# substitute the reason from the template
	$template =~ s/\@\@\@REASON\@\@\@/$reason/g;
	$template = Encode::encode('utf8', $template);

# print the HTML header
	print("Status: 200\r\n", "Content-type: text/html\r\n\r\n")
	or $isfcgi or die "FM error when writing to stdout: $!\n ";
	#print STDERR "DM OK1\n";
	$isfcgi or STDOUT->flush();
	$request->Flush();
# print the template page!
	print($template)
	or $isfcgi or die "FM error when writing to stdout: $!\n ";
	$isfcgi or STDOUT->flush();
	#print STDERR "DM OK2\n";
}

sub abort_request {
	my ($reason) = (@_);
	$exit_requested = 1;
	print STDERR "fatal error, request aborted, shutting down: <$reason>\n";
	$request->Finish();
}


$notifier = Linux::Inotify2->new();
$notifier->blocking(0);
$request = FCGI::Request();
$isfcgi = $request->IsFastCGI();

foreach my $blocktype (@blocktypes) {
	foreach my $filetype (@filetypes) {
		my $filename = "${filetype}-${blocktype}";
		my $filepath = "$incoming/$filename";
		$readconfig{$filepath} = 1;
		$notifier->watch($filepath, Linux::Inotify2::IN_DELETE_SELF|Linux::Inotify2::IN_CLOSE_WRITE, \&watch_callback);
	}
}

while ($handling_request = ($request->Accept() >= 0)) {
	check_config();
	eval {

# here the creation of the html output page actually happens!
		do_request();
	};
	if ($@ && $@ ne 'SIGPIPE\n') {
		my $reason = $@;
		eval {
			abort_request($reason);
		};
	} else {
		$isfcgi or STDOUT->flush();
		$request->Flush();
		$request->Finish();
	}
	$handling_request = 0;
	$exit_requested and last;
}

$request->Finish();
exit(0);
