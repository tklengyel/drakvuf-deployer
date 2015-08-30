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

#include <libxenvchan.h>
#include <xenstore.h>

static const char* xs_watcher_path = "/drakvuf-deployer/client-domid";
static const char* xs_input_path = "/drakvuf-deployer/%i/in"; // server's input, our output
static const char* xs_output_path = "/drakvuf-deployer/%i/out"; // server's output, our input

static struct xs_handle *xs;
static int my_domid;
static struct libxenvchan *vchan_out, *vchan_in;

/* Interrupt handler */
static int interrupted;
static void close_handler(int sig) {
	interrupted = sig;
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

int init_my_domid() {
	xs_transaction_t th;

    int rc = 0;
	int size1 = 0, size2=0;
	char* id = xs_read(xs, th, "domid", &size1);
	if (size1 <= 0 || !id) {
		printf("Failed to access xenstore\n");
		goto done;
	}

	my_domid = atoi(id);

	printf("My domain ID is %i\n", my_domid);

    char* watcher_id = xs_read(xs, th, xs_watcher_path, &size2);
    if (size2 <= 0 || !watcher_id) {
        printf("Failed to access xenstore\n");
        goto done;
    }

    if (atoi(watcher_id) != my_domid) {
        // Save the new (this) domid into Xenstore
        xs_transaction_t th;
        if (!xs_write(xs, th, xs_watcher_path, id, size1)) {
            printf("Failed to save client domid into Xenstore\n");
        }
    } else {
        printf("Server vchan is already setup\n");
    }

    done:
        free(id);
        free(watcher_id);
        return rc;
}

int init_vchan() {
	int rc = 0, size = 0;

	char *input_path = malloc(snprintf(NULL, 0, xs_output_path, my_domid)+1);
    memset(input_path,0,snprintf(NULL, 0, xs_output_path, my_domid)+1);
	sprintf(input_path, xs_output_path, my_domid);
	vchan_in = libxenvchan_client_init(NULL, 0, input_path);
	free(input_path);

	char *output_path = malloc(snprintf(NULL, 0, xs_input_path, my_domid) + 1);
    memset(output_path,0,snprintf(NULL, 0, xs_input_path, my_domid)+1);
	sprintf(output_path, xs_input_path, my_domid);
	vchan_out = libxenvchan_client_init(NULL, 0, output_path);
	free(output_path);

	if (!vchan_in) {
		printf("Failed to init input channel!\n");
		goto done;
	}

	if (!vchan_out) {
		printf("Failed to init encryption channel!\n");
		goto done;
	}

	vchan_in->blocking = 1;
	vchan_out->blocking = 1;

	rc = 1;

	done: return rc;
}

int main(int argc, char **argv) {

	unsigned int rc = 0;
	/* for a clean exit */
	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	xs = xs_open(0);
	if (!xs) {
		printf("Failed to open Xenstore!\n");
		goto done;
	}

	if (!init_my_domid()) {
		goto done;
	}

	if (!init_vchan()) {
		goto done;
	}

	while (!interrupted) {
		char string[1024];

		printf("Enter string for encryption:\n");

		fgets(string, 1024, stdin);
		if (interrupted)
			break;

		char encrypted[4096], decrypted[4096];
		unsigned char *newtext = NULL;
		size_t size = strlen(string);
		string[size - 1] = '\0';
		size_t sent = 0;

		printf("Sending '%s' for encryption\n", string);
		while (sent < size) {
			int rc = libxenvchan_write(vchan_out, string + sent, size - sent);
			if (rc > 0) {
				sent += rc;
			} else {
				printf("Error\n");
				break;
			}
		}

		size_t size_read = libxenvchan_read(vchan_in, encrypted, 4096);
		if (size_read > 0) {
			printf("\tEncrypted string: '%s'\n", encrypted);
		} else {
			printf("Failed to receive encrypted string\n");
			continue;
		}
	}

	done: vchan_finish();
	xs_close(xs);

	return 0;
}
