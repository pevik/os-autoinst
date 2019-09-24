# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019 Petr Vorel <pvorel@suse.cz>

package consoles::sshXtermVtSUT;

use strict;
use warnings;

use base 'consoles::localXvnc';

sub screen {
    # we have no screen (speed up console testing)
    return;
}

1;
