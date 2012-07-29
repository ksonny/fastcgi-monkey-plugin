#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dbg.h"
#include "fcgi_config.h"
#include "MKPlugin.h"

void fcgi_config_free(struct fcgi_config *config)
{
	int i;
	struct fcgi_location *locp;
	struct fcgi_server *srvp;

	if (config->locations) {
		for (i = 0; i < config->location_count; i++) {
			locp = config->locations + i;

			regfree(&locp->match_regex);

			if (locp->name) {
				mk_api->mem_free(locp->name);
			}

			if (locp->servers) {
				mk_api->mem_free(locp->servers);
			}
		}

		mk_api->mem_free(config->locations);
		config->location_count = 0;
		config->locations = NULL;
	}


	if (config->servers) {
		for (i = 0; i < config->server_count; i++) {
			srvp = config->servers + i;
			if (srvp->name) {
				mk_api->mem_free(srvp->name);
			}
			if (srvp->path) {
				mk_api->mem_free(srvp->path);
			}
			if (srvp->addr) {
				mk_api->mem_free(srvp->addr);
			}
		}

		mk_api->mem_free(config->servers);
		config->server_count = 0;
		config->servers = NULL;
	}
}

static int fcgi_validate_conf(struct fcgi_config *config)
{
	int i, j;
	struct fcgi_location *locp;
	struct fcgi_server *srvp;
	ptrdiff_t srv_i;
	uint8_t used_servers[config->server_count];

	check(config->server_count > 0, "No servers configured.");
	check(config->location_count > 0, "No locations configured.");
	check(config->location_count < UINT16_MAX, "Too many locations.");

	for (i = 0; i < config->server_count; i++) {
		used_servers[i] = 0;
	}

	for (i = 0; i < config->location_count; i++) {

		locp = config->locations + i;

		check(locp->server_count > 0,
			"No servers configured for location %d.", i);

		for (j = 0; j < locp->server_count; j++) {
			srv_i = locp->servers[j] - config->servers;
			check(srv_i >= 0 && srv_i < config->server_count,
				"Location server index out of range.");
			used_servers[srv_i] += 1;
		}
	}

	for (i = 0; i < config->server_count; i++) {

		srvp = config->servers + i;

		check(used_servers[i] < 2,
			"Server %s used by multiple locations.", srvp->name);

		if (used_servers[i] == 0) {
			log_warn("Server %s is unused.", srvp->name);
		}

		check((srvp->addr && srvp->port) || srvp->path,
			"No valid socket for server %s.", srvp->name);
		if (srvp->port > 0) {
			check(srvp->port > 0 && srvp->port < 65535,
				"Port out of range for server %s.", srvp->name);
			if (srvp->port < 1023) {
				log_warn("Server %s uses privileged port %d.",
					srvp->name, srvp->port);
			}
		}
	}

	return 0;
error:
	return -1;
}

int fcgi_config_read_server(struct fcgi_server *srv,
		struct mk_config_section *section)
{
	char *tmp = NULL;

	srv->name = mk_api->config_section_getval(section,
		"ServerName", MK_CONFIG_VAL_STR);
	srv->path = mk_api->config_section_getval(section,
		"ServerPath", MK_CONFIG_VAL_STR);

	srv->addr = mk_api->config_section_getval(section,
		"ServerAddr", MK_CONFIG_VAL_STR);
	if (srv->addr) {
		tmp = strchr(srv->addr, ':');
		check(tmp, "No :port in ServerAddr %s", srv->addr);
		*tmp = '\0';
		tmp++;
		check(sscanf(tmp, "%d", &srv->port) == 1,
			"Failed to read :port of ServerAddr %s", srv->addr);
	}

	tmp = mk_api->config_section_getval(section,
		"Multiplexing", MK_CONFIG_VAL_BOOL);
	if (tmp) {
		srv->mpx_connection = !strcasecmp(tmp, VALUE_ON);
		mk_api->mem_free(tmp);
	} else {
		srv->mpx_connection = MK_FALSE;
	}

	srv->max_connections = (long int)mk_api->config_section_getval(section,
		"MaxConnectionss", MK_CONFIG_VAL_NUM);
	srv->max_requests = (long int)mk_api->config_section_getval(section,
		"MaxRequests", MK_CONFIG_VAL_NUM);

	check(srv->name,
		"Server decleration ignored, no ServerName.");
	check(srv->addr || srv->path,
		"Server decleration ignored, no ServerAddr or ServerPath.");
	return 0;
error:
	if (srv->addr && tmp) mk_api->mem_free(tmp);
	return -1;
}

int fcgi_config_read_location(struct fcgi_location *loc,
		struct fcgi_server *servers,
		int server_count,
		struct mk_config_section *section)
{
	int ret = 0;
	char error_str[80];
	int loc_server_n = 0;
	int loc_server_i = 0;
	int i;
	char *regex = NULL;
	char *server_names = NULL;
	char *keep_alive = NULL;
	char *tok;

	regex = mk_api->config_section_getval(section, "Match",
			MK_CONFIG_VAL_STR);
	keep_alive = mk_api->config_section_getval(section, "KeepAlive",
			MK_CONFIG_VAL_STR);
	server_names = mk_api->config_section_getval(section, "ServerNames",
			MK_CONFIG_VAL_STR);

	check(regex, "No match regex defined for this location.");
	for (tok = regex; *tok != '\0'; tok++) {
		*tok = (*tok == ' ') ? '|' : *tok;
	}
	ret = regcomp(&loc->match_regex, regex, REG_EXTENDED|REG_NOSUB);
	check(!ret, "Regex failure on location.");
	mk_api->mem_free(regex);
	regex = NULL;

	if (keep_alive) {
		loc->keep_alive = !strcasecmp(keep_alive, VALUE_ON);
		mk_api->mem_free(keep_alive);
	} else {
		loc->keep_alive = MK_FALSE;
	}

	check(server_names, "No servers for this location.");
	for (i = 0; i < (int)strlen(server_names); i++) {
		if (server_names[i] == ' ')
			loc_server_n += 1;
	}
	loc_server_n += 1;

	loc->servers = mk_api->mem_alloc_z(loc_server_n * sizeof(*loc->servers));
	check_mem(loc->servers);

	for (tok = strtok(server_names, ", "); tok; tok = strtok(NULL, ", ")) {
		for (i = 0; i < server_count; i++) {
			if (strcmp(servers[i].name, tok))
				continue;

			loc->servers[loc_server_i] = servers + i;
			loc_server_i++;
		}
	}
	check(loc_server_i, "Non of servers in ServerNames declared.");
	loc->server_count = loc_server_i;
	mk_api->mem_free(server_names);

	return 0;
error:
	if (ret) {
		regerror(ret, &loc->match_regex, error_str, 80);
		log_err("Regex compile failed: %s", error_str);
	}
	regfree(&loc->match_regex);
	if (loc->servers) mk_api->mem_free(loc->servers);
	if (server_names) mk_api->mem_free(server_names);
	if (keep_alive) mk_api->mem_free(keep_alive);
	if (regex) mk_api->mem_free(regex);
	return -1;
}

int fcgi_config_read(struct fcgi_config *fconf, char *confdir)
{
	unsigned long len;
	char *conf_path = NULL;

	struct mk_config *config = NULL;
	struct mk_config_section *section;
	struct mk_list *head;

	struct fcgi_server *serverp = NULL;
	struct fcgi_location *locationp = NULL;

	int global_count   = 0;
	int server_count   = 0;
	int location_count = 0;

	mk_api->str_build(&conf_path, &len, "%s/fastcgi.conf", confdir);
	config = mk_api->config_create(conf_path);
	mk_api->mem_free(conf_path);

	mk_list_foreach(head, &config->sections) {
		section = mk_list_entry(head, struct mk_config_section, _head);

		if (!strcasecmp(section->name, "FASTCGI")) {
			global_count += 1;
		} else if (!strcasecmp(section->name, "FASTCGI_LOCATION")) {
			location_count += 1;
		} else if (!strcasecmp(section->name, "FASTCGI_SERVER")) {
			server_count += 1;
		}
	}

	check(global_count <= 1, "More then one FASTCGI section. %d", global_count);
	check(server_count > 0, "No FASTCGI_SERVER sections.");
	check(location_count > 0, "No FASTCGI_LOCATION sections.");

	serverp = mk_api->mem_alloc_z(server_count * sizeof(*serverp));
	check_mem(serverp);

	locationp = mk_api->mem_alloc_z(location_count * sizeof(*locationp));
	check_mem(locationp);

	fconf->server_count = server_count;
	fconf->servers = serverp;

	mk_list_foreach(head, &config->sections) {
		section = mk_list_entry(head, struct mk_config_section, _head);

		if (!strcasecmp(section->name, "FASTCGI_SERVER")) {
			check(!fcgi_config_read_server(serverp, section),
				"Failed to parse server configuration.");
			serverp++;
		}
	}

	fconf->location_count = location_count;
	fconf->locations = locationp;

	mk_list_foreach(head, &config->sections) {
		section = mk_list_entry(head, struct mk_config_section, _head);

		if (!strcasecmp(section->name, "FASTCGI_LOCATION")) {
			check(!fcgi_config_read_location(locationp,
					fconf->servers,
					fconf->server_count,
					section),
				"Failed to parse location configuration.");
			locationp++;
		}
	}

	check(!fcgi_validate_conf(fconf),
		"Failed to validate configuration.");
	mk_api->config_free(config);
	return 0;
error:
	if (config) mk_api->config_free(config);
	fcgi_config_free(fconf);
	return -1;
}

struct fcgi_location *fcgi_config_get_location(struct fcgi_config *config,
		int location_id)
{
	check(location_id >= 0 && location_id < config->location_count,
		"Location id out of range: %d.", location_id);

	return config->locations + location_id;
error:
	return NULL;
}

struct fcgi_server *fcgi_config_get_server(struct fcgi_config *config,
		int server_id)
{
	check(server_id >= 0 && server_id < config->server_count,
		"Server id out of range: %d.", server_id);

	return config->servers + server_id;
error:
	return NULL;
}
