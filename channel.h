// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef CHANNELS_H__
#define CHANNELS_H__

void channel_wrch(int ch, int reg);
void channel_rdch(int ch, int reg);
int channel_rchcnt(int ch);

#endif
