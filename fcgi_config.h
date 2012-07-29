#ifndef _FCGI_CONFIG_H_
#define _FCGI_CONFIG_H_

#include "mk_list.h"
#include "regex.h"

struct fcgi_server {
	char *name;
	char *path;
	char *addr;
	int port;

	int mpx_connection;

	int max_connections;
	int max_requests;
};

struct fcgi_location {
	char *name;
	regex_t match_regex;

	int keep_alive;

	int server_count;
	struct fcgi_server **servers;
};

struct fcgi_config {
	int server_count;
	struct fcgi_server *servers;
	int location_count;
	struct fcgi_location *locations;
};

void fcgi_config_free(struct fcgi_config *config);

int fcgi_config_read(struct fcgi_config *config, char *confdir);

struct fcgi_location *fcgi_config_get_location(struct fcgi_config *config,
		int location_id);

struct fcgi_server *fcgi_config_get_server(struct fcgi_config *config,
		int server_id);

#endif // _FCGI_CONFIG_H
