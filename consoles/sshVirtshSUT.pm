# Copyright © 2018-2019 SUSE LLC
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

package consoles::sshVirtshSUT;

use strict;
use warnings;

use base 'consoles::console';

use testapi 'get_var';
use consoles::virtio_screen;

sub new {
    bmwqemu::fctwarn("=== pev: sshVirtshSUT::new()"); # FIXME: debug
    my ($class, $testapi_console, $args) = @_;

    my $self = $class->SUPER::new($testapi_console, $args);

    # TODO: inherit from consoles::sshVirtsh
    my $instance = get_var('VIRSH_INSTANCE', 1);
    $self->{libvirt_domain} = $args->{libvirt_domain} // "openQA-SUT-$instance";
    $self->{serial_port_no} = $args->{serial_port_no} // 1;

    # QEMU on s390x fails to start when added <serial> device due arch limitation
    # on SCLP console, see "Multiple VT220 operator consoles are not supported"
    # error at
    # https://github.com/qemu/qemu/blob/master/hw/char/sclpconsole.c#L226
    # Therefore <console> must be used for s390x.
    # ATM there is only s390x using this console, let's make it the default.
    $self->{pty_dev} = $args->{pty_dev} // 'console';

    return $self;
}

sub screen {
    bmwqemu::fctwarn("=== pev: sshVirtshSUT::screen()"); # FIXME: debug
    my ($self) = @_;
    return $self->{screen};
}

sub disable {
    bmwqemu::fctwarn("=== pev: sshVirtshSUT::disable()"); # FIXME: debug
    my ($self) = @_;

    bmwqemu::fctwarn("pev: before disconnect");
    if (my $ssh = $self->{ssh}) {
        bmwqemu::fctwarn("pev: DISCONNECT");
        $ssh->disconnect;
        $self->{ssh} = $self->{chan} = $self->{screen} = undef;
    }
    return;
}

sub activate {
    bmwqemu::fctwarn("=== pev: sshVirtshSUT::activate() (create SSH)"); # FIXME: debug
    my ($self) = @_;

    my $backend = $self->{backend};
    my ($ssh, $chan) = $backend->open_serial_console_via_ssh($self->{libvirt_domain},
        devname => $self->{pty_dev}, port => $self->{serial_port_no}, is_terminal => 1);

    $self->{ssh}    = $ssh;
    $self->{screen} = consoles::virtio_screen->new($chan, $ssh->sock);
    bmwqemu::fctwarn("=== pev: sshVirtshSUT::activate() END"); # FIXME: debug
    return;
}

sub is_serial_terminal {
    return 1;
}

1;
