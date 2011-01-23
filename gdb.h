// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef GDB_H__
#define GDB_H__

#include <signal.h>
#include "types.h"

#ifdef _WIN32
#define SIGTRAP 5
#define	SIGTERM		15
#define MSG_WAITALL  8
#endif

typedef enum {
	GDB_BP_TYPE_NONE = 0,
	GDB_BP_TYPE_X,
	GDB_BP_TYPE_R,
	GDB_BP_TYPE_W,
	GDB_BP_TYPE_A
} gdb_bp_type;

void gdb_init(u32 port);
void gdb_deinit(void);

void gdb_handle_events(void);
int gdb_signal(u32 signal);

int gdb_bp_x(u32 addr);
int gdb_bp_r(u32 addr);
int gdb_bp_w(u32 addr);
int gdb_bp_a(u32 addr);

#endif
