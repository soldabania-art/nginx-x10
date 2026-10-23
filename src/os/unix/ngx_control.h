
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONTROL_H_INCLUDED_
#define _NGX_CONTROL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


void ngx_control_generation_start(ngx_cycle_t *cycle);
void ngx_control_generation_commit(ngx_cycle_t *cycle);
void ngx_control_process_spawned(ngx_cycle_t *cycle, ngx_int_t slot, ngx_pid_t pid,
    ngx_uint_t detached);
void ngx_control_preinit(void);
ngx_int_t ngx_control_init(u_char *addr);
void ngx_control_uninit(void);
void ngx_control_close_sockets(void);
char *ngx_control_handoff(void);
void ngx_control_reown(void);
ngx_int_t ngx_control_handle_events(void);


extern ngx_uint_t  ngx_control_api_enabled;


#endif /* _NGX_CONTROL_H_INCLUDED_ */
