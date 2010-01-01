/*
 *  Apple iPhone USB Ethernet pairing program
 *
 *  Copyright (c) 2009 Daniel Borca  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libiphone/lockdown.h>


int
main(int argc, char **argv)
{
    const char *myself = argv[0];
    char *host_id = NULL;
    char *uuid = NULL;
    int list = 0;

    iphone_error_t rv;
    iphone_device_t device;
    lockdownd_client_t client;

    while (--argc) {
	const char *p = *++argv;
	if (!strcmp(p, "--help") || !strcmp(p, "-h")) {
	    printf("usage: %s [--list] [--uuid UUID] [--host HOSTID]\n", myself);
	    return 1;
	}
	if (!strcmp(p, "--list") || !strcmp(p, "-l")) {
	    list = !0;
	    break;
	}
	if (!strcmp(p, "--uuid") || !strcmp(p, "-u")) {
	    if (argc < 2) {
		fprintf(stderr, "%s: argument to '%s' is missing\n", myself, p);
		return -1;
	    }
	    argc--;
	    uuid = *++argv;
	    continue;
	}
	if (!strcmp(p, "--host")) {
	    if (argc < 2) {
		fprintf(stderr, "%s: argument to '%s' is missing\n", myself, p);
		return -1;
	    }
	    argc--;
	    host_id = *++argv;
	    continue;
	}
    }

    if (list) {
	int err = 0;
	int i, count;
	char **devices;

	rv = iphone_get_device_list(&devices, &count);
	if (rv || !count) {
	    fprintf(stderr, "%s: no devices\n", myself);
	    return -1;
	}
	for (i = 0; i < count; i++) {
	    char *device_name = NULL;
	    rv = iphone_device_new(&device, devices[i]);
	    if (rv == 0) {
		rv = lockdownd_client_new(device, &client);
		if (rv == 0) {
		    rv = lockdownd_get_device_name(client, &device_name);
		    lockdownd_client_free(client);
		}
		iphone_device_free(device);
	    }
	    printf("%s %s\n", devices[i], device_name ? device_name : "N/A");
	    free(device_name);
	    err |= rv;
	}

	iphone_device_list_free(devices);
	return err;
    }

    rv = iphone_device_new(&device, uuid);
    if (rv) {
	fprintf(stderr, "%s: cannot get %s device\n", argv[0], uuid ? uuid : "default");
	return -1;
    }
    rv = lockdownd_client_new(device, &client);
    if (rv) {
	fprintf(stderr, "%s: cannot get lockdown\n", argv[0]);
	iphone_device_free(device);
	return -1;
    }
    if (host_id != NULL) {
	/* lockdownd_client_new() already Pair'ed with stock host_id.
	 * Redo Pair with this one, otherwise ValidatePair will fail.
	 */
	rv = lockdownd_pair(client, host_id);
	if (rv) {
	    fprintf(stderr, "%s: cannot Pair\n", argv[0]);
	    lockdownd_client_free(client);
	    iphone_device_free(device);
	    return -1;
	}
    }
    rv = lockdownd_validate_pair(client, host_id);
    if (rv) {
	fprintf(stderr, "%s: cannot ValidatePair\n", argv[0]);
	lockdownd_client_free(client);
	iphone_device_free(device);
	return -1;
    }

    /* Is it ok to say Goodbye? */
    lockdownd_client_free(client);
    iphone_device_free(device);

    return 0;
}
