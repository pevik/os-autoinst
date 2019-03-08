# Copyright © 2009-2013 Bernhard M. Wiedemann
# Copyright © 2012-2019 SUSE LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

package backend::svirt;

use strict;
use warnings;

use base 'backend::virt';

use File::Basename;
use IO::Scalar;
use IO::Select;

use testapi qw(get_var get_required_var check_var);

# this is a fake backend to some extend. We don't start VMs, but provide ssh access
# to a libvirt running host (KVM for System Z in mind)

use constant SERIAL_TERMINAL_LOG_PATH => 'serial_terminal.txt';

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new;
    get_required_var('WORKER_HOSTNAME');

    return $self;
}

# we don't do anything actually
sub do_start_vm {
    my ($self) = @_;

    my $vars = \%bmwqemu::vars;
    my $n    = $vars->{NUMDISKS} || 1;
    $vars->{NUMDISKS} ||= defined($vars->{RAIDLEVEL}) ? 4 : $n;

    # truncate the serial file
    open(my $sf, '>', $self->{serialfile});
    close($sf);

    my $ssh = $testapi::distri->add_console(
        'svirt',
        'ssh-virtsh',
        {
            hostname => get_required_var('VIRSH_HOSTNAME'),
            username => get_var('VIRSH_USERNAME'),
            password => get_var('VIRSH_PASSWORD'),
        });

    $ssh->backend($self);

    bmwqemu::save_vars();    # update variables
    return {};
}

sub do_stop_vm {
    my ($self) = @_;

    $self->stop_serial_grab;

    unless (get_var('SVIRT_KEEP_VM_RUNNING')) {
        my $vmname = $self->console('svirt')->name;
        bmwqemu::diag "Destroying $vmname virtual machine";
        if (check_var('VIRSH_VMM_FAMILY', 'hyperv')) {
            my $ps = 'powershell -Command';
            $self->run_ssh_cmd("$ps Stop-VM -Force -VMName $vmname -TurnOff");
            $self->run_ssh_cmd("$ps Remove-VM -Force -VMName $vmname");
        }
        else {
            my $virsh = 'virsh';
            $virsh .= ' ' . get_var('VMWARE_REMOTE_VMM') if get_var('VMWARE_REMOTE_VMM');
            $self->run_ssh_cmd("$virsh destroy $vmname");
            $self->run_ssh_cmd("$virsh undefine --snapshots-metadata $vmname");
        }
    }

    # TODO: stream serial_terminal.txt with scp on the fly instead
    $self->scp_get($self->serial_terminal_log_file(), SERIAL_TERMINAL_LOG_PATH);
    $self->delete_log();

    return {};
}

# Log stdout and stderr and return them in a list (comped).
sub get_ssh_output {
    my ($chan) = @_;
    die('No channel found') unless $chan;

    my ($stdout, $stderr) = ('', '');
    while (!$chan->eof) {
        if (my ($o, $e) = $chan->read2) {
            $stdout .= $o;
            $stderr .= $e;
        }
    }
    chomp($stdout, $stderr);
    bmwqemu::diag("Command's stdout:\n$stdout") if length($stdout);
    bmwqemu::diag("Command's stderr:\n$stderr") if length($stderr);
    return ($stdout, $stderr);
}

=head2 run_cmd($ssh, $cmd, %args);
Runs command to libvirt host over SSH, logs stdout and stderr of the command.

Returns either exit code itself or with stdout and stderr (both in blocking
mode. C<$args{nonblock}> is for long running process, returns $ssh and $sock
for handling the process.

# Examples:
    my $ret = $svirt->run_cmd($ssh, "virsh snapshot-create-as snap1");
    die "snapshot creation failed" unless $ret == 0;

    my ($ret, $stdout, $stderr) = $svirt->run_cmd($ssh, "grep -q '$marker' $log");
    my ($ssh, $chan) = $svirt->run_cmd($ssh, $cmd_full, nonblock => 1);
=cut
sub run_cmd {
    my ($ssh, $cmd, %args) = @_;
    bmwqemu::log_call(@_);

    my $chan = $ssh->channel();
    die('No channel found') unless $chan;

    $chan->exec($cmd);
    if ($args{nonblock}) {
        bmwqemu::diag("Run command: '$cmd' (nonblock)");
        return ($ssh, $chan);
    }

    my ($stdout, $errout) = get_ssh_output($chan);
    $chan->send_eof;
    my $ret = $chan->exit_status();
    bmwqemu::diag("Command executed: '$cmd', ret=$ret");
    $chan->close();

    if (wantarray) {
        bmwqemu::fctwarn("pev: WANTARAY"); # FIXME: debug
        return ($ret, $stdout, $errout);
    }
    bmwqemu::fctwarn("pev: NO WANTARAY"); # FIXME: debug
    return $ret;
}

=head2
See parameters and examples at C<run_cmd>.
=cut
sub run_ssh_cmd {
    my ($self, $cmd, %args) = @_;
    bmwqemu::log_call(@_);
    my $credentials = $self->read_credentials_from_virsh_variables;
    my $self->{ssh} = $self->new_ssh_connection(%$credentials);

    if ($args{nonblock}) {
        bmwqemu::fctwarn("pev: CALL run_cmd, nonblock: " . $args{nonblock}); # FIXME: debug
    } else {
        bmwqemu::fctwarn("pev: CALL run_cmd, no nonblock"); # FIXME: debug
    }
    return run_cmd($self->{ssh}, $cmd, %args);
}

sub scp_get {
    my ($self, $src, $dest) = @_;
    bmwqemu::log_call(@_);

    my $credentials = $self->read_credentials_from_virsh_variables;
    my $ssh         = $self->new_ssh_connection(%$credentials);

    open(my $fh, '>', $dest) or die "Could not open file '$dest' $!";
    bmwqemu::diag("SCP file: '$src' => '$dest'");
    my $output = IO::Scalar->new;
    $ssh->scp_get($src, $output) or die "SCP failed";
    print $fh $output;
    close $fh;
    $ssh->disconnect();
}

sub can_handle {
    my ($self, $args) = @_;
    my $vars = \%bmwqemu::vars;
    if ($args->{function} eq 'snapshots' && !check_var('HDDFORMAT', 'raw')) {
        # Snapshots via libvirt are supported on KVM and, perhaps, ESXi. Hyper-V uses native tools.
        if (check_var('VIRSH_VMM_FAMILY', 'kvm') || check_var('VIRSH_VMM_FAMILY', 'hyperv') || check_var('VIRSH_VMM_FAMILY', 'vmware')) {
            return {ret => 1};
        }
    }
    return;
}

sub is_shutdown {
    my ($self) = @_;
    my $vmname = $self->console('svirt')->name;
    my $rsp;
    if (check_var('VIRSH_VMM_FAMILY', 'hyperv')) {
        $rsp = $self->run_ssh_cmd("powershell -Command \"if (\$(Get-VM -VMName $vmname \| Where-Object {\$_.state -eq 'Off'})) { exit 1 } else { exit 0 }\"");
    }
    else {
        my $libvirt_connector = get_var('VMWARE_REMOTE_VMM', '');
        $rsp = $self->run_ssh_cmd("! virsh $libvirt_connector dominfo $vmname | grep -w 'shut off'");
    }
    return $rsp;
}

sub save_snapshot {
    my ($self, $args) = @_;
    my $snapname = $args->{name};
    my $vmname   = $self->console('svirt')->name;
    my $rsp;
    if (check_var('VIRSH_VMM_FAMILY', 'hyperv')) {
        my $ps = 'powershell -Command';
        $self->run_ssh_cmd("$ps Remove-VMSnapshot -VMName $vmname -Name $snapname");
        $rsp = $self->run_ssh_cmd("$ps Checkpoint-VM -VMName $vmname -SnapshotName $snapname");
    }
    else {
        my $libvirt_connector = get_var('VMWARE_REMOTE_VMM', '');
        $self->run_ssh_cmd("virsh $libvirt_connector snapshot-delete $vmname $snapname");
        $rsp = $self->run_ssh_cmd("virsh $libvirt_connector snapshot-create-as $vmname $snapname");
    }
    bmwqemu::diag "SAVE VM $vmname as $snapname snapshot, return code=$rsp";
    $self->die unless ($rsp == 0);
    return;
}

sub load_snapshot {
    my ($self, $args) = @_;
    my $snapname = $args->{name};
    my $vmname   = $self->console('svirt')->name;
    my $rsp;
    my $post_load_snapshot_command = '';
    if (check_var('VIRSH_VMM_FAMILY', 'hyperv')) {
        my $ps = 'powershell -Command';
        $rsp = $self->run_ssh_cmd("$ps Restore-VMSnapshot -VMName $vmname -Name $snapname -Confirm:\$false");
        $self->run_ssh_cmd("mv -v xfreerdp_${vmname}_stop xfreerdp_${vmname}_stop.bkp");
        for my $i (1 .. 5) {
            # Because of FreeRDP issue https://github.com/FreeRDP/FreeRDP/issues/3876,
            # we can't connect too "early". Let's have a nap for a while.
            sleep 10;
            last
              unless $self->run_ssh_cmd(
                "pgrep --full --list-full xfreerdp.*\$(cat xfreerdp_${vmname}_stop.bkp)");
            $self->die("xfreerdp did not start") if ($i eq 5);
        }
    }
    else {
        my $libvirt_connector = get_var('VMWARE_REMOTE_VMM', '');
        $rsp                        = $self->run_ssh_cmd("virsh $libvirt_connector snapshot-revert $vmname $snapname");
        $post_load_snapshot_command = 'vmware_fixup' if check_var('VIRSH_VMM_FAMILY', 'vmware');
    }
    bmwqemu::diag "LOAD snapshot $snapname to $vmname, return code=$rsp";
    $self->die if $rsp;
    return $post_load_snapshot_command;
}

sub read_credentials_from_virsh_variables {
    my ($self) = @_;

    my ($hostname, $username, $password);
    if (check_var('VIRSH_VMM_FAMILY', 'hyperv')) {
        $hostname = get_required_var('VIRSH_GUEST');
        $password = get_var('VIRSH_GUEST_PASSWORD');
    }
    else {
        $hostname = get_required_var('VIRSH_HOSTNAME');
        $username = get_var('VIRSH_USERNAME');
        $password = get_var('VIRSH_PASSWORD');
    }
    return {
        hostname => $hostname,
        username => ($username // 'root'),
        password => $password,
    };
}

sub start_serial_grab {
    my ($self, $name) = @_;

    my $credentials = $self->read_credentials_from_virsh_variables;
    my $chan        = $self->start_ssh_serial(%$credentials);
    if (check_var('VIRSH_VMM_FAMILY', 'vmware')) {
        # libvirt esx driver does not support `virsh console', so
        # we have to connect to VM's serial port via TCP which is
        # provided by ESXi server.
        $chan->exec('nc ' . get_var('VMWARE_HOST') . ' ' . get_var('VMWARE_SERIAL_PORT'));
    }
    elsif (check_var('VIRSH_VMM_FAMILY', 'hyperv')) {
        # Hyper-V does not support serial console export via TCP, just
        # windows named pipes (e.g. \\.\pipe\mypipe). Such a named pipe
        # has to be enabled by a namedpipe-to-TCP on HYPERV_SERVER application.
        $chan->exec('nc ' . get_var('HYPERV_SERVER') . ' ' . get_var('HYPERV_SERIAL_PORT'));
    }
    else {
        $chan->exec('virsh console ' . $name);
    }
}

=head2 ($ssh, $chan) = $self->backend->start_serial_grab($name, %args)

Opens SSH connection to grab the serial console for kernel log (serial0.txt)
or serial terminal log (serial_terminal.txt).

C<$args{port}> used non-default port (used for serial_terminal.txt)
C<$args{devname}> used device name (usually console, for serial_terminal.txt)
C<$args{is_terminal}> for serial terminal (usually console, for serial_terminal.txt)
=cut
sub open_serial_console_via_ssh {
    my ($self, $name, %args) = @_;
    my ($chan, $cmd, $cmd_full, $ret, $ssh, $stderr, $stdout);
    my $port   = $args{port} // '';
    my $devname = $args{devname} // '';
    my $marker = "CONSOLE_EXIT:";
    my $log    = $self->serial_terminal_log_file();

    if (check_var('VIRSH_VMM_FAMILY', 'vmware')) {
        # libvirt esx driver does not support `virsh console', so
        # we have to connect to VM's serial port via TCP which is
        # provided by ESXi server.
        $cmd = 'nc ' . get_var('VMWARE_HOST') . ' ' . $port;
    }
    elsif (check_var('VIRSH_VMM_FAMILY', 'hyperv')) {
        # Hyper-V does not support serial console export via TCP, just
        # windows named pipes (e.g. \\.\pipe\mypipe). Such a named pipe
        # has to be enabled by a namedpipe-to-TCP on HYPERV_SERVER application.
        $cmd = 'nc ' . get_var('HYPERV_SERVER') . ' ' . $port;
    }
    else {
        $cmd = "virsh console $name $devname$port";
    }

    $cmd_full = "script -f $log -c '$cmd; echo \"$marker \$?\"'";
    bmwqemu::diag("Starting SSH connection to connect to libvirt domain '$name' (cmd: '$cmd'), full cmd: '$cmd_full'");

    bmwqemu::fctwarn("!!! pev: BEFORE '$cmd_full'"); # FIXME: debug
    ($ssh, $chan) = $self->run_ssh_cmd($cmd_full, nonblock => 1);
    bmwqemu::fctwarn("pev: AFTER '$cmd_full'"); # FIXME: debug

    # FIXME: debug
    bmwqemu::fctwarn("pev: ref(ssh): '" . ref($ssh) . "'"); # FIXME: debug
    bmwqemu::fctwarn("pev: dumpxml:"); # FIXME: debug
    ($ret, $stdout, $stderr) = $self->run_ssh_cmd("virsh dumpxml $name");
    # FIXME: debug

    ($ret, $stdout, $stderr) = $self->run_ssh_cmd("grep -q '$marker' $log");
    bmwqemu::fctwarn("pev: ret: $ret"); # FIXME: debug
    if (!$ret) {
        (undef, $stdout, undef) = $self->run_ssh_cmd("cat $log");
        $self->die("problem with virsh: cmd: '$cmd', output of script wrapper: '$stdout')");
    }

    bmwqemu::fctwarn("pev: BEFORE RETURN ref(ssh): '" . ref($ssh) . "'"); # FIXME: debug
    return ($ssh, $chan);
}

sub delete_log
{
    my ($self) = $_;
    my $log = $self->serial_terminal_log_file();
    $self->run_ssh_cmd("[ -f '\$log' ] && rm -v \$log; done");
}

# TODO: use CORE::GLOBAL::die
sub die
{
    my ($self, $err) = $_;
    bmwqemu::diag("error, cleanup logs before die");
    $self->delete_log();
    die $err;
}

sub serial_terminal_log_file {
    my ($self) = @_;
    return "/tmp/" . SERIAL_TERMINAL_LOG_PATH . '.'
    . get_required_var('JOBTOKEN');
}

sub check_socket {
    my ($self, $fh, $write) = @_;

    if ($self->check_ssh_serial($fh)) {
        return 1;
    }
    return $self->SUPER::check_socket($fh, $write);
}

sub stop_serial_grab {
    my ($self) = @_;

    $self->stop_ssh_serial;
    return;
}

1;

# vim: set sw=4 et:
