/*
 * Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006-2007 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     o Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the <ORGANIZATION> nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __COMMAND_H
#define __COMMAND_H

typedef struct {
	unsigned char *data;
	size_t size;
} cmd_data_t;

void cmd_free_data (assuan_context_t ctx);
int cmd_getinfo (assuan_context_t ctx, char *line);
int cmd_serialno (assuan_context_t ctx, char *line);
int cmd_learn (assuan_context_t ctx, char *line);
int cmd_readcert (assuan_context_t ctx, char *line);
int cmd_readkey (assuan_context_t ctx, char *line);
int cmd_setdata (assuan_context_t ctx, char *line);
int cmd_pksign (assuan_context_t ctx, char *line);
int cmd_pkdecrypt (assuan_context_t ctx, char *line);
int cmd_random (assuan_context_t ctx, char *line);
int cmd_checkpin (assuan_context_t ctx, char *line);
int cmd_getinfo (assuan_context_t ctx, char *line);
int cmd_restart (assuan_context_t ctx, char *line);

#endif
