// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "main.h"
#include "config.h"
#include "elf.h"
#include "emulate.h"
#include "gdb.h"

struct ctx_t _ctx;
struct ctx_t *ctx;

static int gdb_port = -1;
static const char *elf_path = NULL;

void dump_regs(void)
{
	u32 i;

	printf("\nRegister dump:\n");
	printf(" pc:\t%08x\n", ctx->pc);
	for (i = 0; i < 128; i++)
		printf("%.3d:\t%08x %08x %08x %08x\n",
				i,
				ctx->reg[i][0],
				ctx->reg[i][1],
				ctx->reg[i][2],
				ctx->reg[i][3]
				);
}

void dump_ls(void)
{
	FILE *fp;

	printf("dumping local store to " DUMP_LS_NAME "\n");
	fp = fopen(DUMP_LS_NAME, "wb");
	fwrite(ctx->ls, LS_SIZE, 1, fp);
	fclose(fp);
}

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	perror(msg);

#ifdef FAIL_DUMP_REGS
	dump_regs();
#endif

#ifdef FAIL_DUMP_LS
	dump_ls();
#endif

	gdb_deinit();
	exit(1);
}

static void usage(void)
{
	printf("usage: anergistic [-g 1234] filename.elf\n");
	exit(1);
}

static void parse_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "g:")) != -1) {
		switch(c) {
			case 'g':
				gdb_port = strtol(optarg, NULL, 10);
				break;
			default:
				printf("Unknown argument: %c\n", c);
				usage();
		}
	}

	if (optind != argc - 1)
		usage();

	elf_path = argv[optind];
}

int main(int argc, char *argv[])
{
	u32 done;
	memset(&_ctx, 0x00, sizeof _ctx);
	ctx = &_ctx;
	parse_args(argc, argv);

#if 0
	u64 local_ptr;
	
	local_ptr = 0xdead0000dead0000ULL;
	
	ctx->reg[3][0] = (u32)(local_ptr >> 32);
	ctx->reg[3][1] = (u32)local_ptr;

	ctx->reg[4][0] = 0xdead0000;
	ctx->reg[4][1] = 0xdead0000;
#endif

	ctx->ls = malloc(LS_SIZE);
	if (ctx->ls == NULL)
		fail("Unable to allocate local storage.");
	memset(ctx->ls, 0, LS_SIZE);

#if 1
	wbe64(ctx->ls + 0x3f000, 0x100000000ULL);
	wbe32(ctx->ls + 0x3f008, 0x10000);
	wbe32(ctx->ls + 0x3e000, 0xff);
#endif

	if (gdb_port < 0) {
		ctx->paused = 0;
	} else {
		gdb_init(gdb_port);
		ctx->paused = 1;
		gdb_signal(SIGABRT);
	}

	elf_load(elf_path);

	done = 0;

	while(done == 0) {

		if (ctx->paused == 0)
			done = emulate();

		// data watchpoints
		if (done == 2) {
			ctx->paused = 0;
			gdb_signal(SIGTRAP);
			done = 0;
		}
		
		if (done != 0) {
			printf("emulated() returned, sending SIGSEGV to gdb stub\n");
			ctx->paused = 1;
			done = gdb_signal(SIGSEGV);
		}

		if (done != 0) {
#ifdef STOP_DUMP_REGS
			dump_regs();
#endif
#ifdef STOP_DUMP_LS
			dump_ls();
#endif
		}

		if (ctx->paused == 1)
			gdb_handle_events();
	}
	printf("emulate() returned. we're done!\n");
	dump_ls();
	free(ctx->ls);
	gdb_deinit();
	return 0;
}
