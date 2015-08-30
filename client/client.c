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
#include <signal.h>
#include <poll.h>
#include <pthread.h>

#include <xenstore.h>

static const char* xs_base_path = "/drakvuf-deployer";
static const char* xs_init_path = "/drakvuf-deployer/init";
static const char* xs_input_path = "/drakvuf-deployer/input";
static const char* xs_output_path = "/drakvuf-deployer/output";

static const char* reset = "reset";
static pthread_t client;
pthread_mutex_t mutex;

static struct xs_handle *xs;
static int my_domid;

/* Interrupt handler */
static int interrupted;
static void close_handler(int sig) {
	interrupted = sig;
}

void received_reset_result(char *result) {
    printf("Reset result: %s\n", result);
}

void* client_thread(void* input) {
    xs_transaction_t th;
    int rc, num_strings, len;
    char **vec, *buf = NULL;
    struct pollfd fd = { .fd = xs_fileno(xs), .events = POLLIN | POLLERR };

    while (pthread_mutex_trylock(&mutex)) {
        sleep(1);
    }

    pthread_mutex_unlock(&mutex);

    while (!interrupted) {
        // For some reason polling on xenstore doesn't work in the client
        // xs_read_watch would get stuck and hang the process
        // so we just sleep-loop waiting for the result
        th = xs_transaction_start(xs);
        buf = xs_read(xs, th, xs_output_path, &len);
        xs_transaction_end(xs, th, false);

        if (buf)
            break;
        else
            sleep(1);
    }

    if (buf) {
        th = xs_transaction_start(xs);
        xs_rm(xs, th, xs_output_path);
        xs_transaction_end(xs, th, false);

        received_reset_result(buf);
        free(buf);
    }

done:
    pthread_exit(NULL);
    return NULL;
}

int init_xenstore() {
	xs_transaction_t th;
    int rc = 0;
	int size1 = 0, size2=0;

	xs = xs_open(0);
	if (!xs) {
		printf("Failed to open Xenstore!\n");
		goto done;
	}

    th = xs_transaction_start(xs);
	char* id = xs_read(xs, th, "domid", &size1);
    xs_transaction_end(xs, th, false);

	if (size1 <= 0 || !id) {
		printf("Failed to access xenstore\n");
		goto done;
	}

	my_domid = atoi(id);

	printf("My domain ID is %i\n", my_domid);

    th = xs_transaction_start(xs);
    char* init = xs_read(xs, th, xs_init_path, &size2);
    xs_transaction_end(xs, th, false);

    if (!init) {
        printf("Failed to access xenstore for drakvuf init path\n");
        goto done;
    }

    rc = 1;

done:
    free(id);
    free(init);
    return rc;
}

int main(int argc, char **argv) {

	int rc = 0, len;
	xs_transaction_t th;

    interrupted = 0;

    /* for a clean exit */
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if(!init_xenstore())
        goto done;

    th = xs_transaction_start(xs);
    char *buf = xs_read(xs, th, xs_output_path, &len);
    xs_transaction_end(xs, th, false);

    if (!buf) {
        pthread_mutex_init(&mutex, NULL);
        pthread_mutex_lock(&mutex);
        pthread_create(&client, NULL, client_thread, NULL);

        th = xs_transaction_start(xs);
        rc = xs_write(xs, th, xs_input_path, reset, strlen(reset));
        xs_transaction_end(xs, th, false);

        pthread_mutex_unlock(&mutex);

        if (!rc) {
            printf("Failed to send reset signal\n");
            goto done;
        }

        pthread_join(client,NULL);

    } else {
        th = xs_transaction_start(xs);
        xs_rm(xs, th, xs_output_path);
        xs_transaction_end(xs, th, false);
        received_reset_result(buf);
    }

    done:
    interrupted = 1;
    pthread_mutex_destroy(&mutex);
    xs_close(xs);

    return 0;
}
