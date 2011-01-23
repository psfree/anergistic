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
#include "channel.h"

static u32 MFC_LSA, MFC_EAH, MFC_EAL, MFC_Size, MFC_TagID, MFC_TagMask, MFC_TagStat;

#define MFC_GET_CMD 0x40
#define MFC_SNDSIG_CMD 0xA0


void handle_mfc_command(u32 cmd)
{
	printf("Local address %08x, EA = %08x:%08x, Size=%08x, TagID=%08x, Cmd=%08x\n",
		MFC_LSA, MFC_EAH, MFC_EAL, MFC_Size, MFC_TagID, cmd);
	switch (cmd)
	{
	case MFC_GET_CMD:
		printf("MFC_GET (DMA into LS)\n");
#if 0
		{
			FILE *f = fopen("dma", "rb");
			if (!f)
				exit(1);
			fseek(f, MFC_EAL, SEEK_SET);
			if (fread(ctx->ls + MFC_LSA, 1, MFC_Size, f) != MFC_Size)
			{
				printf("read error\n");
				exit(1);
			}
			fclose(f);
		}
#endif
		break;
	default:
		printf("unknown command\n");
	}
}

void handle_mfc_tag_update(u32 tag)
{
	switch (tag)
	{
	case 0:
		MFC_TagStat = MFC_TagMask;
		break;
	default:
		printf("unknown tag update\n");
		break;
	}
}

void channel_wrch(int ch, int reg)
{
	printf("CHANNEL: wrch ch%d r%d\n", ch, reg);
	u32 r = ctx->reg[reg][0];
	
	switch (ch)
	{
	case 16:
		printf("MFC_LSA %08x\n", r);
		MFC_LSA = r;
		break;
	case 17:
		printf("MFC_EAH %08x\n", r);
		MFC_EAH = r;
		break;
	case 18:
		printf("MFC_EAL %08x\n", r);
		MFC_EAL = r;
		break;
	case 19:
		printf("MFC_Size %08x\n", r);
		MFC_Size = r;
		break;
	case 20:
		printf("MFC_TagID %08x\n", r);
		MFC_TagID =r ;
		break;
	case 21:
		printf("MFC_Cmd %08x\n", r);
		handle_mfc_command(r);
		break;
	case 22:
		printf("MFC_WrTagMask %08x\n", r);
		MFC_TagMask = r;
		break;
	case 23:
		printf("MFC_WrTagUpdate %08x\n", r);
		handle_mfc_tag_update(r);
		break;
	case 26:
		printf("MFC_WrListStallAck %08x\n", r);
		break;
	case 27:
		printf("MFC_RdAtomicStat %08x\n", r);
		break;
	default:
		printf("UNKNOWN CHANNEL\n");
	}
}

void channel_rdch(int ch, int reg)
{
	printf("CHANNEL: rdch ch%d r%d\n", ch, reg);
	u32 r;
	
	r = 0;
	switch (ch)
	{
	case 24:
		r = MFC_TagStat;
		printf("MFC_RdTagStat %08x\n", r);
		break;
	case 27:
		printf("MFC_RdAtomicStat %08x\n", r);
		break;
	}
	ctx->reg[reg][0] = r;
	ctx->reg[reg][1] = 0;
	ctx->reg[reg][2] = 0;
	ctx->reg[reg][3] = 0;
}

int channel_rchcnt(int ch)
{
	u32 r;
	r = 0;
	switch (ch)
	{
	case 23:
		r = 1;
		break;
	case 24:
		r = 1;
		printf("MFC_RdTagStat %08x\n", r);
		break;
	case 27:
		printf("MFC_RdAtomicStat %08x\n", r);
		break;
	default:
		printf("unknown channel %d\n", ch);
	}
	return r;
}
