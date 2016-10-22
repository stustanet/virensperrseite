#!/usr/bin/perl

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

my @blocktypes = ( 'dynamic', 'permanent' );

my @filetypes = ( 'blocklist', 'error_page_template' );

my $incoming = '/home/scp-rec/incoming';
#my $incoming = '.';

my %templates;

my %blocklists;

my %readconfig;

my $stats;
my $updates = 0;


my $handling_request = 0;
my $exit_requested = 0;

my $notifier;
my $request;
my $isfcgi;

sub sig_handler_exit {
	$exit_requested = 1;
	$handling_request or exit(0);
}

$SIG{USR1} = \&sig_handler_exit;
$SIG{TERM} = \&sig_handler_exit;
$SIG{PIPE} = sub { die 'SIGPIPE\n'; };


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

sub load_blocklist {
	my ($blocktype, $filepath) = (@_);

	my %block;

	#print STDERR "load_blocklist: $blocktype, $filepath\n";
	eval {
		my $fh = IO::File->new($filepath) or die "can't read $filepath: $!\n ";
		while (defined(my $line = <$fh>)) {
			$line =~ /^#/ and next;
			my ($ip, $reason) = split(/\s+#\s+/, $line, 2);
			defined($ip) or next;
			defined($reason) or $reason = "Virus/Trojaner/Stoerer";
			$reason =~ s/\&/\&amp;/g;
			$reason =~ s/\</\&lt;/g;
			$reason =~ s/\>/\&gt;/g;
			$ip = NetAddr::IP->new($ip);
			defined($ip) or next;
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
		$fh->error and die "error when read $filepath: $!\n ";
		$block{error} = "Virus/Trojaner/Stoerer";
	};
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

sub do_request() {
	# ip-adresse bestimmen
	my $pathinfo = $ENV{SCRIPT_NAME};
	if (! defined($pathinfo)) {
		do_errorpage();
		return;
	}
	my ($dummy1, $scriptname, $type, $arg1) = split(/\//, $pathinfo);
	if (! defined($type) || ! defined($arg1)) {
		do_errorpage();
		return;
	}
	if ($type eq 'blocked') {
		defined($arg1) or $arg1 = 'error';
	} elsif ($type eq 'error') {
		$arg1 = 'error';
	} else {
		do_errorpage();
		return;
	}
	my $ip = NetAddr::IP->new($arg1);
	defined($ip) and $arg1 = $ip->addr;
	my $reason;
	my $blocktype;
	foreach my $b (@blocktypes) {
		if ($blocklists{$b} && ($reason = $blocklists{$b}->{$arg1})) {
			$blocktype = $b;
			last;
		}
	}
	if (! defined($reason)) {
		$blocktype = $blocktypes[0];
		$reason = $blocklists{$blocktype}->{error};
	}
	my $template = $templates{$blocktype};

	$template =~ s/\@\@\@REASON\@\@\@/$reason/g;
	$template = Encode::encode('utf8', $template);

	print("Status: 404\r\n", "Content-type: text/html\r\n\r\n")
	or $isfcgi or die "FM error when writing to stdout: $!\n ";
	#print STDERR "DM OK1\n";
	$isfcgi or STDOUT->flush();
	$request->Flush();
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
