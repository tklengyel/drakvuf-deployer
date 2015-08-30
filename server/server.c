/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/
#include <config.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <libxenvchan.h>
#include <xenstore.h>

/* Xenstore paths */
static const char* xs_watcher_path = "/drakvuf-deployer/client-domid";
static const char* xs_input_path = "/drakvuf-deployer/%i/in";
static const char* xs_output_path = "/drakvuf-deployer/%i/out";

/* Vchan structs */
static struct libxenvchan *vchan_in, *vchan_out;

/* Xenstore handle */
static struct xs_handle *xs;

/* Threads for encryption/decryption */
static pthread_t server, watcher;

/* Whether a server is already active */
static int server_active;

/* The domain ID we are running in */
static int my_domid;

/* Interrupt handler */
static int watcher_interrupted, server_interrupted;
static void close_handler(int sig) {
	watcher_interrupted = sig;
    server_interrupted = sig;
}

static inline
void vchan_finish() {
	if (vchan_in) {
		libxenvchan_close(vchan_in);
        vchan_in = NULL;
	}
	if (vchan_out) {
		libxenvchan_close(vchan_out);
        vchan_out = NULL;
	}
}

/* Initialize channels for encryption and decryption */
int vchan_init(int peer_domid) {

	int ret = 0;

    char *input_path = malloc(snprintf(NULL, 0, xs_input_path, peer_domid) + 1);
    memset(input_path,0,snprintf(NULL, 0, xs_input_path, peer_domid)+1);
    sprintf(input_path, xs_input_path, peer_domid);

    char *output_path = malloc(snprintf(NULL, 0, xs_output_path, peer_domid) + 1);
    memset(output_path,0,snprintf(NULL, 0, xs_output_path, peer_domid)+1);
    sprintf(output_path, xs_output_path, peer_domid);

	vchan_in = libxenvchan_server_init(NULL, peer_domid, input_path, 0, 0);
	vchan_out = libxenvchan_server_init(NULL, peer_domid, xs_output_path, 0, 0);

	if (!vchan_in) {
		printf("Failed to init input channel for %s\n", input_path);
		goto done;
	}

	if (!vchan_out) {
		printf("Failed to init output channel!\n", output_path);
		goto done;
	}

	// Set channel to blocking
	vchan_in->blocking = 1;
	vchan_in->server_persist = 1;
	vchan_out->blocking = 1;
	vchan_out->server_persist = 1;

	printf("Event channels opened for peer domain %i\n", peer_domid);
	printf("\tInput port: %u. Output port: %u\n", vchan_in->event_port, vchan_out->event_port);

	// Save the server's domid into Xenstore
	/*xs_transaction_t th;
	char *domid_str = malloc(snprintf(NULL, 0, "%i", my_domid) + 1);
	sprintf(domid_str, "%i", my_domid);
	if (!xs_write(xs, th, "/vtpm/aes/server_domid", domid_str,
			strlen(domid_str))) {
		printf("Failed to save server domid into Xenstore\n");
		ret = 0;
	}
	free(domid_str);*/

    ret = 1;

	done:
        free(input_path);
        free(output_path);
        return ret;
}

void *server_thread(void *input) {

	int mode = *(int *) input;

	printf("Starting DRAKVUF Deployer Server\n");
    server_interrupted = 0;
    server_active = 1;

	while (!server_interrupted) {
		unsigned char buffer[32];
		memset(buffer, 0, 32);
		int size = 0, sent = 0;

		size = libxenvchan_read(vchan_in, buffer, 32);
		if (size > 0) {

			while (sent < size) {
                unsigned char *newtext = "OK";
				int rc = libxenvchan_write(vchan_out, newtext + sent, size - sent);
				if (rc > 0) {
					sent += rc;
				} else {
					printf("Error\n");
					break;
				}
			}
		}

	}

	printf("Stopping DRAKVUF Deployer Server\n");
	vchan_finish();
	pthread_exit(NULL);

	return NULL;
}

/* Xenstore poller to create DRAKVUF deployer vchan server
 * This is used to watch for the client domid */
void* watcher_thread(void* input) {

    fd_set set;
    xs_transaction_t th;
    unsigned int len, num_strings;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 0 };
    char **vec, *buf;

    if ( !xs_watch(xs, xs_watcher_path, "drakvuf-deployer") )
        goto done;

    int fd = xs_fileno(xs);

    while (!watcher_interrupted) {

        FD_ZERO(&set);
        FD_SET(fd, &set);

        /* Poll for data. */
        if ( select(fd + 1, &set, NULL, NULL, &tv) > 0 && FD_ISSET(fd, &set)) {
            vec = xs_read_watch(xs, &num_strings);
            if (!vec || !num_strings) goto done;

            if (num_strings == 2)
            printf("vec contents: %s|%s\n", vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);

            /* Prepare a transaction and do a read. */
            th = xs_transaction_start(xs);
            buf = xs_read(xs, th, vec[XS_WATCH_PATH], &len);
            xs_transaction_end(xs, th, false);
            if ( buf ) {
                printf("buflen: %d\nbuf: %s\n", len, buf);

        	    if (!vchan_init(atoi(buf))) {
		            printf("Couldn't initialize Xen inter-domain communication channel (vchan)\n");
        	    }

                if (server_active) {
                    server_interrupted = 1;
                	pthread_join(server, NULL);
                }

            	pthread_create(&server, NULL, server_thread, NULL);
            }
        }
    }

    done:
    	pthread_exit(NULL);
	    return NULL;

}

void init_my_domid() {
	xs_transaction_t th;

	int size = 0;
	char* id = xs_read(xs, th, "domid", &size);
	if (size <= 0 || !id) {
		printf("Failed to access xenstore\n");
		return;
	}

	my_domid = atoi(id);
	free(id);

	printf("My domain ID is %i\n", my_domid);
}

int xenstore_init() {
	xs = xs_open(0);
	if (!xs) {
		return 0;
	}

	return 1;
}

void xenstore_close() {
	if (xs) {
		xs_close(xs);
		xs = NULL;
	}
}

int main(int argc, char **argv) {

	int ret = 0;
    server_active = 0;
	server_interrupted = 0;
    watcher_interrupted = 0;

    vchan_in = NULL;
    vchan_out = NULL;

	if (!xenstore_init()) {
		printf("Failed to open Xenstore!\n");
		ret = -1;
		goto done;
	}

	init_my_domid();

	/* for a clean exit */
	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	pthread_create(&watcher, NULL, watcher_thread, NULL);
	pthread_join(watcher, NULL);

    if (server_active)
        pthread_join(server, NULL);

	xenstore_close();

	done: return ret;
}
