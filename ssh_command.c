/*
 * MIT License
 *
 * Copyright (c) 2018 Lewis Van Winkle
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//#include "chap11.h"
//chap11.h orignally contaied the following

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libssh/libssh.h>
// end of libraies 

int main(int argc, char *argv[])
{
    //if (argc < 4) {
    //    fprintf(stderr, "Usage: ssh_command hostname port user\n");
    //    return 1;
    //}
    const char *hostname = argv[1];
    int port = 22;
    const char *user = "zodiac";


    ssh_session ssh = ssh_new();
    if (!ssh) {
        fprintf(stderr, "ssh_new() failed.\n");
        return 1;
    }

    ssh_options_set(ssh, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);
    ssh_options_set(ssh, SSH_OPTIONS_USER, user);

    int ret = ssh_connect(ssh);
    if (ret != SSH_OK) {
        fprintf(stderr, "ssh_connect() failed.\n%s\n", ssh_get_error(ssh));
        return -1;
    }

    //printf("Connected to %s on port %d.\n", hostname, port);

    //printf("Banner:\n%s\n", ssh_get_serverbanner(ssh));



    ssh_key key;
    if (ssh_get_server_publickey(ssh, &key) != SSH_OK) {
        fprintf(stderr, "ssh_get_server_publickey() failed.\n%s\n",
                ssh_get_error(ssh));
        return -1;
    }

    unsigned char *hash;
    size_t hash_len;
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA1,
                &hash, &hash_len) != SSH_OK) {
        fprintf(stderr, "ssh_get_publickey_hash() failed.\n%s\n",
                ssh_get_error(ssh));
        return -1;
    }

    //printf("Host public key hash:\n");
    //ssh_print_hash(SSH_PUBLICKEY_HASH_SHA1, hash, hash_len);

    ssh_clean_pubkey_hash(&hash);
    ssh_key_free(key);




    //printf("Checking ssh_session_is_known_server()\n");
    enum ssh_known_hosts_e known = ssh_session_is_known_server(ssh);
    switch (known) {
        case SSH_KNOWN_HOSTS_OK: break; // printf("Host Known.\n"); break;

        case SSH_KNOWN_HOSTS_CHANGED: printf("Host Changed.\n"); break;
        case SSH_KNOWN_HOSTS_OTHER: printf("Host Other.\n"); break;
        case SSH_KNOWN_HOSTS_UNKNOWN: printf("Host Unknown.\n"); break;
        case SSH_KNOWN_HOSTS_NOT_FOUND: printf("No host file.\n"); break;

        case SSH_KNOWN_HOSTS_ERROR:
            printf("Host error. %s\n", ssh_get_error(ssh)); return 1;

        default: printf("Error. Known: %d\n", known); return 1;
    }



    if (known == SSH_KNOWN_HOSTS_CHANGED ||
            known == SSH_KNOWN_HOSTS_OTHER ||
            known == SSH_KNOWN_HOSTS_UNKNOWN ||
            known == SSH_KNOWN_HOSTS_NOT_FOUND) {
        printf("Do you want to accept and remember this host? Y/N\n");
        char answer[10];
        fgets(answer, sizeof(answer), stdin);
        if (answer[0] != 'Y' && answer[0] != 'y') {
            return 0;
        }

        ssh_session_update_known_hosts(ssh);
    }

    //Originally had passwords for auto ssh to old password protected STB's
    char password[][20] = { };
    for ( int i = 0; i < 4 ; i++ ) {
        if (ssh_userauth_password(ssh, 0, password[i]) == SSH_AUTH_SUCCESS) {
            //printf("Authentication successful!\n");
            //printf("%s\n", argv[2]);
            if (!strcmp(argv[2], "-p")) {
                printf("%s\n", password[i]);
                return 0;
            }
            break;
        } else {
            ssh_get_error(ssh);
        }
    }

    ssh_channel channel = ssh_channel_new(ssh);
    if (!channel) {
        fprintf(stderr, "ssh_channel_new() failed.\n");
        return 0;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "ssh_channel_open_session() failed.\n");
        return 0;
    }
    //printf("Remote command to execute: ");
    //char command[128];
    //fgets(command, sizeof(command), stdin);

    //printf("%s",argv[2]);
    //printf(" %s\n",argv[3]);
    if (argc > 2 ) {
        char command[28] = "";
        for ( int y = 2; y < argc; y++ ) {
                int re = strcmp(argv[y], ",");
                if ( re == 0 ){
                        printf("%s\n",command);
                        command[sizeof(command)-1];
                        strncpy(command, "", sizeof(command));
                }
                else {
                        strcat(command, argv[y]);
                        strcat(command, " ");
                }
        }
    command[sizeof(command)-1];
    //char * test[]={ "profile get", "cds group" };
    char * test[]={ "profile get" };
    for( int z = 0; z < sizeof(test)/sizeof(char *) ; z++ ){
        printf("%s\n",test[z]);
    if (ssh_channel_request_exec(channel, test[z] ) != SSH_OK) {
        fprintf(stderr, "ssh_channel_open_session() failed.\n");
        return 1;
    }
}

    char output[1024];
    int bytes_received;
    while ((bytes_received =
                ssh_channel_read(channel, output, sizeof(output), 0))) {
        if (bytes_received < 0) {
            //fprintf(stderr, "ssh_channel_read() failed.\n");
            return 1;
        }
        printf("%.*s", bytes_received, output);
    }
    }


    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    ssh_disconnect(ssh);
    ssh_free(ssh);

    return 0;
}
