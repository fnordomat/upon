/**
 * upon(TM) for Linux(TM) version 0.0.1
 *
 * fnordomat <GPG:46D46D1246803312401472B5A7427E237B7908CA>
 *
 * Listens for process events (fork, exec, change uid/gid, and exit)
 * through a kernel connector and executes actions based on them.
 *
 * Currently implemented: run another command upon exec or exit (which is
 * then, together with its progeny, excluded from matching action rules),
 * sigstop matching processes upon exec.
 *
 * Requires CONFIG_CONNECTOR=y CONFIG_PROC_EVENTS=y in kernel config.
 *
 * CAVEAT:  not guaranteed to be 100% reliable, because the connector buffers
 * only boundedly many events and the kernel can't wait for our lowly program
 * to retrieve them (obviously). Under load, events may be missed.
 *
 * Based on existing code, cobbled together by fnordomat in 2019. Pedigree:
 *
 * cn_proc functionality -
 *   Derived from exec-notify.c  by Sebastian Krahmer
 *   Derived from test_cn_proc.c by Matt Helsley
 *   Derived from fcctl.c        by Guillaume Thouvenin
 * ADMIN_NET_CAP code etc. -
 *   Derived from waitforpid.c   by Christian Storm
 *   Inspired by startmon        by Philip J. Turmel
 *   Inspired by a blog entry    by Scott James Remnant
 *
 *
 * original copyright comments follow:
 *
 *
 * waitforpid - wait for a (non-child) process' exit using Linux's
 *              PROC_EVENTS and POSIX capabilities.
 *
 * Copyright (C) 2014 Christian Storm <christian.storm@tngtech.com>
 *
 *
 * Inspired by startmon (http://github.com/pturmel/startmon)
 * Copyright (C) 2011 Philip J. Turmel <philip@turmel.org>
 * which was inspired by a blog entry by Scott James Remnant:
 * http://netsplit.com/2011/02/09/the-proc-connector-and-socket-filters/
 *
 *
 * exec-notify, so you can watch your acrobat reader or vim executing "bash -c"
 * commands ;-)
 * Requires some 2.6.x Linux kernel with proc connector enabled.
 *
 * $  cc -Wall -ansi -pedantic -std=c99 exec-notify.c
 *
 * (C) 2007-2010 Sebastian Krahmer <krahmer@suse.de> original netlink handling
 * stolen from an proc-connector example, copyright folows:
 *
 *
 * Copyright (C) Matt Helsley, IBM Corp. 2005
 * Derived from fcctl.c by Guillaume Thouvenin
 * Original copyright notice follows:
 *
 * Copyright (C) 2005 BULL SA.
 * Written by Guillaume Thouvenin <guillaume.thouvenin@bull.net>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sysexits.h>

#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>
#include <linux/limits.h>

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define max(x,y) ((y)<(x)?(x):(y))
#define min(x,y) ((y)>(x)?(x):(y))

#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))

#define PROC_CN_MCAST_LISTEN (1)
#define PROC_CN_MCAST_IGNORE (2)

#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Support being run setuid root
#define ALLOW_ROOT 0
// Use POSIX capabilities (ALLOW_ROOT=0 recommended)
#define USE_CAPS   1

extern int errno;

static __uid_t original_uid;
static __gid_t original_gid;
static int cmax;
static enum what *eventType;
static char **target;
static int  * target_pid;
static char **action;
static int verbosity = 0;

static int sk_nl;

static cap_t capabilities = NULL;

static int close_socket() {
    if (sk_nl != -1) {
        return close(sk_nl);
    }
    return 0;
}

static void free_capabilities() {
    if (capabilities != NULL) {
        (void)cap_free(capabilities);
    }
}

static void signal_handler(const int sig) {
    switch(sig){
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
            close_socket();
            free_capabilities();
            exit(EXIT_SUCCESS);
    }
}

struct PidNode {
    pid_t pid;
    struct PidNode* next;
};
static struct PidNode* ignored = NULL;

void initIgn() {
    ignored = (struct PidNode*)malloc(sizeof(struct PidNode));
    ignored->next = NULL;
    ignored->pid  = getpid();
}

void deinitIgn() {
    for (struct PidNode* it = ignored; it != NULL; it = it->next) {
        struct PidNode* next = it->next;
        free(it);
        it = next;
    }
}

int isIgnored(pid_t pid) {
    for (struct PidNode* it = ignored; it != NULL; it = it->next) {
        if (it->pid == pid) {
            if (verbosity >= 3) {
                printf("Found %d on ignore list.\n", pid);
            }
            return 1;
        }
    }
    if (verbosity >= 3) {
        printf("Did not find %d on ignore list.\n", pid);
    }
    return 0;
}

// Returns 1 if pid was found in list and removed, 0 otherwise.
int unignorePid(pid_t pid) {
    struct PidNode* last = ignored;
    for (struct PidNode* it = last->next; it != NULL; last = it, it = it->next) {
        if (it->pid == pid) {
            last->next = it->next;
            free(it);
            it = last;

            if (verbosity >= 3) {
                printf("Removed %d from ignore list.\n", pid);
            }
            return 1;
        }
    }

    if (verbosity >= 3) {
        printf("Did not find %d on ignore list.\n", pid);
    }
    return 0;
}

void ignorePid(pid_t pid) {
    for (struct PidNode* it = ignored; it != NULL; it = it->next) {
        if (it->pid == pid) {
            if (verbosity >= 3) {
                printf("Already found %d on ignore list.\n", pid);
            }
            return;
        }
        else if (it->next == NULL) {
            it->next = (struct PidNode*)malloc(sizeof(struct PidNode));
            it->next->next = NULL;
            it->next->pid = pid;
            if (verbosity >= 3) {
                printf("Added %d to ignore list.\n", pid);
            }
            return;
        }
    }
}

void handle_msg(struct cn_msg *cn_hdr) {
    // apparently limited to PAGE_SIZE, which is 4096:
    char cmdline[4096];
    char fname_status[PATH_MAX], fname_cmdline[PATH_MAX];

    int fd, i;
    ssize_t r=0;

    struct proc_event* ev = (struct proc_event*)cn_hdr->data;

    snprintf(fname_status,  sizeof(fname_status),  "/proc/%d/status",  ev->event_data.exec.process_pid);
    snprintf(fname_cmdline, sizeof(fname_cmdline), "/proc/%d/cmdline", ev->event_data.exec.process_pid);

    fd = open(fname_cmdline, O_RDONLY);

    memset(&cmdline, 0, sizeof(cmdline));

    if (PROC_EVENT_EXIT == ev->what) {
        if (verbosity >= 2) {
            printf(ANSI_COLOR_CYAN "EXIT: pid=%d" ANSI_COLOR_RESET "\n", ev->event_data.exit.process_pid);
        }
        if (unignorePid(ev->event_data.exit.process_pid)) {
            return;
        }
    }

    if (fd > 0) {
        r = read(fd, cmdline, sizeof(cmdline));
        close(fd);

        for (i = 0; r > 0 && i < r - 1; // trailing '\0'
             ++i) {
            if (cmdline[i] == 0) cmdline[i] = ' ';
        }
    }

    if (PROC_EVENT_EXEC == ev->what) {
        if (verbosity >= 2) {
            printf(ANSI_COLOR_CYAN "EXEC: pid=%d [%s]" ANSI_COLOR_RESET "\n", ev->event_data.exec.process_pid, cmdline);
        }
        if (isIgnored(ev->event_data.exec.process_pid)) {
            return;
        }
    }
    else if (PROC_EVENT_FORK == ev->what) {
        if (verbosity >= 2) {
            printf(ANSI_COLOR_CYAN "FORK: parent=%d child=%d [%s]" ANSI_COLOR_RESET "\n",
               ev->event_data.fork.parent_pid,
               ev->event_data.fork.child_pid, cmdline);
        }
        if (isIgnored(ev->event_data.fork.parent_pid)) {
            ignorePid(ev->event_data.fork.child_pid);
            return;
        }
    }

    for (int c=0; c<cmax; ++c) {
        if (eventType[c] == ev->what) {

            int match = 0;
            if (target[c] != NULL) { match = (cmdline == strstr(cmdline, target[c])); }
            else {
                int test_pid = 0;
                switch (ev->what) {
                case PROC_EVENT_EXEC:
                    test_pid = ev->event_data.exec.process_pid;
                    break;
                case PROC_EVENT_EXIT:
                    test_pid = ev->event_data.exit.process_pid;
                    break;
                case PROC_EVENT_FORK:
                    test_pid = ev->event_data.fork.child_pid;
                    break;
                default:
                    fprintf(stderr, "Warning: test for pid not yet implemented for event type %x\n", ev->what);
                    return;
                }
                match = (target_pid[c] == test_pid);
            }
            if (match) {
                if (NULL != strstr(action[c], "sigstop")) {
                    if (verbosity > 0) {
                        printf(ANSI_COLOR_YELLOW "Match -- stopping process." ANSI_COLOR_RESET "\n");
                    }
                    kill(ev->event_data.exec.process_pid, SIGSTOP);
                }
                else if (NULL != strstr(action[c], "run ")) {
                    if (verbosity > 0) {
                        printf(ANSI_COLOR_YELLOW "Match -- executing command." ANSI_COLOR_RESET "\n");
                    }

                    if (strlen(action[c]) > 4)
                    {
                        char *executable = action[c]+4;

                        pid_t child;

                        int forkpid = fork();

                        if (forkpid == -1) {
                            fprintf(stderr, "Fork error.\n");
                            exit(EX_OSERR);
                        }
                        else if ((child = forkpid) != 0)
                        {
                            ignorePid(child);
                            // Exclude this pid and all children (later traced via fork events)
                            // from consideration, to eschew infinite loops.
                        }
                        else {
                            char *const args[] = {executable, (char*)NULL};

                            if (execve(executable, args, NULL) == -1) {
                                fprintf(stderr, "Error %s executing %s\n", strerror(errno), executable);
                                exit(EXIT_FAILURE);
                            }
                        }
                    }
                }
            }
        }
    }
}

static void acquire_privileges() {
#if USE_CAPS == 1
    cap_value_t cap_list[1] = { CAP_NET_ADMIN };
    cap_flag_value_t cap_flags_value;

    if (!CAP_IS_SUPPORTED(CAP_NET_ADMIN)) {
        fprintf(stderr, "Capability CAP_NET_ADMIN is not supported\n");
        exit(EXIT_FAILURE);
    }
    if (geteuid() != getuid() && geteuid() == 0) {
        fprintf(stderr, "Suid root is not needed when using CAP_NET_ADMIN.\n");
    }
    if (getegid() != getgid() && getegid() == 0) {
        fprintf(stderr, "Sgid root is not needed when using CAP_NET_ADMIN.\n");
    }

    capabilities = cap_get_proc();
    if (capabilities == NULL) {
        fprintf(stderr, "Cannot get capabilities\n");
        exit(EXIT_FAILURE);
    }

    // Ensure that CAP_NET_ADMIN is permitted
    if (cap_get_flag(capabilities, cap_list[0], CAP_PERMITTED, &cap_flags_value) == -1) {
        fprintf(stderr, "Cannot get CAP_PERMITTED flag value of capability CAP_NET_ADMIN\n");
        exit(EXIT_FAILURE);
    }
    if (cap_flags_value == CAP_CLEAR) {
        fprintf(stderr, "Capability CAP_NET_ADMIN is not CAP_PERMITTED, run setcap CAP_NET_ADMIN=p [executable]\n");
        exit(EXIT_FAILURE);
    }

    // Test if CAP_NET_ADMIN is effective, else make it effective
    if (cap_get_flag(capabilities, cap_list[0], CAP_EFFECTIVE, &cap_flags_value) == -1) {
        fprintf(stderr, "Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
        exit(EXIT_FAILURE);
    }
    if (cap_flags_value == CAP_CLEAR) {
        if (cap_set_flag(capabilities, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
            fprintf(stderr, "Cannot set CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
            exit(EXIT_FAILURE);
        }
        if (cap_set_proc(capabilities) == -1){
            fprintf(stderr, "Cannot set capability CAP_NET_ADMIN to CAP_EFFECTIVE\n");
            exit(EXIT_FAILURE);
        }
        if (cap_get_flag(capabilities, cap_list[0], CAP_EFFECTIVE, &cap_flags_value) == -1) {
            fprintf(stderr, "Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
            exit(EXIT_FAILURE);
        }
        if (cap_flags_value == CAP_CLEAR) {
            fprintf(stderr, "Failed to set capability CAP_NET_ADMIN to CAP_EFFECTIVE\n");
            exit(EXIT_FAILURE);
        }
    }
    (void)cap_free(capabilities);
    capabilities = NULL;
#endif
}

static void drop_privileges() {
#if USE_CAPS == 1
    cap_value_t cap_list[1] = { CAP_NET_ADMIN };
    cap_flag_value_t cap_flags_value;

    capabilities = cap_get_proc();
    if (capabilities == NULL) {
        fprintf(stderr, "Cannot get capabilities\n");
        exit(EXIT_FAILURE);
    }
    if (cap_get_flag(capabilities, cap_list[0], CAP_EFFECTIVE, &cap_flags_value) == -1) {
        fprintf(stderr, "Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
        exit(EXIT_FAILURE);
    }

    // Drop CAP_NET_ADMIN to permitted if it's effective
    if (cap_flags_value == CAP_SET) {
        if (cap_set_flag(capabilities, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR) == -1) {
            fprintf(stderr, "Cannot clear CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
            exit(EXIT_FAILURE);
        }
        if (cap_set_proc(capabilities) == -1){
            fprintf(stderr, "Cannot set capability CAP_NET_ADMIN to CAP_EFFECTIVE\n");
            exit(EXIT_FAILURE);
        }
        if (cap_get_flag(capabilities, cap_list[0], CAP_PERMITTED, &cap_flags_value) == -1) {
            fprintf(stderr, "Cannot get CAP_EFFECTIVE flag value of capability CAP_NET_ADMIN\n");
            exit(EXIT_FAILURE);
        }
        if (cap_flags_value == CAP_CLEAR) {
            fprintf(stderr, "Failed to drop capability CAP_NET_ADMIN privileges to CAP_PERMITTED\n");
            exit(EXIT_FAILURE);
        }
    }
    (void)cap_free(capabilities);
    capabilities = NULL;
#endif

#if ALLOW_ROOT == 1

    printf("Dropping privileges to uid %d, gid %d\n", original_uid, original_gid);

    if (setgid(original_gid) == -1) {
        fprintf(stderr, "Error setgid: %s\n", strerror(errno));
        exit(-1);
    }
    if (setegid(original_gid) == -1) {
        fprintf(stderr, "Error setegid: %s\n", strerror(errno));
        exit(-1);
    }
    if (setuid(original_uid) == -1) {
        fprintf(stderr, "Error setuid: %s\n", strerror(errno));
        exit(-1);
    }
    if (seteuid(original_uid) == -1) {
        fprintf(stderr, "Error seteuid: %s\n", strerror(errno));
        exit(-1);
    }

    if (setuid(0) == 0 || seteuid(0) == 0) {
        fprintf(stderr, "Error: unsuccessful dropping root privileges.\n");
        return -1;
    }
#endif
}

int runMain() {

    // Install signal handler
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (   (sigaction(SIGINT,  &sa, NULL) == -1) \
        || (sigaction(SIGTERM, &sa, NULL) == -1) \
        || (sigaction(SIGQUIT, &sa, NULL) == -1) ) {
        fprintf(stderr, "Cannot install signal handler: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    acquire_privileges();

    // Establish datagram connection between kernel side and this process
    sk_nl = socket(PF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_CONNECTOR);

    if (sk_nl == -1) {
        fprintf(stderr, "Error creating netlink socket.\n");
        return -1;
    }

    struct sockaddr_nl my_nla, kern_nla, from_nla;

    my_nla.nl_family = AF_NETLINK;
    my_nla.nl_groups = CN_IDX_PROC;
    my_nla.nl_pid    = (__u32)getpid();

    kern_nla.nl_family = AF_NETLINK;
    kern_nla.nl_groups = CN_IDX_PROC;
    kern_nla.nl_pid    = 1;

    int rc = bind(sk_nl, (struct sockaddr*)&my_nla, sizeof(my_nla));

    if (rc == -1) {
        fprintf(stderr, "Error binding netlink socket.\n");
        return rc;
    }

    struct nlmsghdr *nl_hdr;
    struct cn_msg   *cn_hdr;
    enum   proc_cn_mcast_op *mcop_msg;

    char buffer[BUFF_SIZE];

    nl_hdr = (struct nlmsghdr*) buffer;
    cn_hdr = (struct cn_msg  *) NLMSG_DATA(nl_hdr);
    mcop_msg = (enum proc_cn_mcast_op*)&cn_hdr->data[0];

    memset(buffer, 0, sizeof(buffer));
    *mcop_msg = PROC_CN_MCAST_LISTEN;

    nl_hdr->nlmsg_len   = SEND_MESSAGE_LEN;
    nl_hdr->nlmsg_type  = NLMSG_DONE;
    nl_hdr->nlmsg_flags = 0;
    nl_hdr->nlmsg_seq   = 0;
    nl_hdr->nlmsg_pid   = (__u32)getpid();

    cn_hdr->id.idx      = CN_IDX_PROC;
    cn_hdr->id.val      = CN_VAL_PROC;
    cn_hdr->seq         = 0;
    cn_hdr->ack         = 0;
    cn_hdr->len         = sizeof(enum proc_cn_mcast_op);

    if (send(sk_nl, nl_hdr, nl_hdr->nlmsg_len, 0) != nl_hdr->nlmsg_len) {
        fprintf(stderr, "Failed to send proc_cn_mcast_op.\n");
        exit(-1);
    }
    
    if (*mcop_msg == PROC_CN_MCAST_IGNORE) {
        fprintf(stderr, "Got PROC_CN_MCAST_IGNORE.\n");
        exit(-1);
    }

    socklen_t from_nla_len;
    ssize_t   recv_len = 0;

    drop_privileges();

    initIgn();

    printf("Reading process events for euid %d from proc connector.\n"
           "Hit Ctrl-C to exit\n", original_uid);

    // main loop

    for (memset(buffer, 0, sizeof(buffer)), from_nla_len = sizeof(from_nla);
       ; memset(buffer, 0, sizeof(buffer)), from_nla_len = sizeof(from_nla)) {
        struct nlmsghdr *nlh = (struct nlmsghdr*)buffer;
        memcpy(&from_nla, &kern_nla, sizeof(from_nla));
        recv_len = recvfrom(sk_nl, buffer, BUFF_SIZE, 0,
                            (struct sockaddr*)&from_nla, &from_nla_len);
        if (from_nla.nl_pid != 0)
            continue;
        while (NLMSG_OK(nlh, recv_len)) {
            cn_hdr = NLMSG_DATA(nlh);
            if (nlh->nlmsg_type == NLMSG_NOOP)
                continue;
            if ((nlh->nlmsg_type == NLMSG_ERROR) ||
                    (nlh->nlmsg_type == NLMSG_OVERRUN))
                break;
            handle_msg(cn_hdr);
            if (nlh->nlmsg_type == NLMSG_DONE)
                break;
            nlh = NLMSG_NEXT(nlh, recv_len);
        }
    }

    deinitIgn();
}

void printUsage()
{
    fprintf(stderr, "Usage: upon [-v] -- tuple1 ...\n");
    fprintf(stderr, "-v : increase verbosity (up to -vvv = DEBUG)\n");
    fprintf(stderr, "tuple:     eventtype match action\n");
    fprintf(stderr, "eventtype: exec\n");
    fprintf(stderr, "match:     p(pid) or m(initial part of process cmdline to filter)\n");
    fprintf(stderr, "action:    sigstop / run [executable]\n");
}

int main(int argc, char ** argv, char ** envp) {

    atexit((void(*)(void))close_socket);
    atexit(free_capabilities);

    // Normally, processes will be filtered by original uid, gid.

    original_uid = getuid();
    original_gid = getgid();
    
    fprintf(stderr, "uid %d, euid %d\n", getuid(), geteuid());

    // Was it perhaps run via sudo? Attempt to find original uid, gid from environment set by sudo.

    if (original_uid == 0) {

        for (char **env = envp; *env != 0; env++)
        {
            char *thisEnv = *env;
            if (strstr(thisEnv, "SUDO_UID=") == thisEnv) {
                __uid_t sudouid;
                // Of course, root could also set the environment variable erroneously.
                if (sscanf(thisEnv+strlen("SUDO_UID="), "%d", &sudouid)) {
                    printf("sudouid %d\n", sudouid);
                    original_uid = sudouid;
                } else {
                    fprintf(stderr, "SUDO_UID bizarre value.\n");
                    return -1;
                }
            }

            if (strstr(thisEnv, "SUDO_GID=") == thisEnv) {
                __gid_t sudogid;
                if (sscanf(thisEnv+strlen("SUDO_GID="), "%d", &sudogid)) {
                    printf("sudogid %d\n", sudogid);
                    original_gid = sudogid;
                } else {
                    fprintf(stderr, "SUDO_GID bizarre value.\n");
                    return -1;
                }
            }

        }
    }

#if (ALLOW_ROOT == 1) && (USE_CAPS == 0)
    if (geteuid() != 0) {
        fprintf(stderr, "Must be run with root privileges.\n");
        // or admin net cap, if so configured
        return -1;
    }
#endif

    if (argc < 4) {
        fprintf(stderr, "Insufficient number of arguments.\n");
        printUsage();
        return -1;
    }

    int c;
    opterr = 0;
    while ((c = getopt (argc, argv, "v")) != -1) {
        switch (c)
        {
        case 'v':
            verbosity ++;
            break;
        }
    }
    fprintf(stderr, "optind = %d\n", optind);

    if ((argc-optind) % 3 != 0) {
        fprintf(stderr, "Wrong number of (non-getopt) arguments.\n");
        printUsage();
        return -1;
    }

    cmax = (argc-optind)/3;

    eventType  = (enum what*)malloc(sizeof(enum what) * cmax);
    target     = (char**)malloc(sizeof(char*) * cmax);
    target_pid = (int*)malloc(sizeof(int) * cmax);
    action     = (char**)malloc(sizeof(char*) * cmax);

    if (eventType == NULL || target == NULL || action == NULL) {
        fprintf(stderr, "Internal error.\n");
        return -1;
    }

    for (int c = 0 ; 3*c < argc-optind ; ++c) {
        if (strstr(argv[3*c + optind], "exec") == argv[3*c + optind]) {
            eventType[c] = PROC_EVENT_EXEC;
        }
        else if (strstr(argv[3*c + optind], "exit") == argv[3*c + optind]) {
            eventType[c] = PROC_EVENT_EXIT;
        }
        else {
            fprintf(stderr, "Unknown event type %s\n", argv[3*c + optind]);
            return -1;
        }

        char* tgt = argv[3*c + optind + 1];
        if (strlen(tgt) < 1 || !((tgt[0] == 'p') || (tgt[0] == 'm'))) {
            fprintf(stderr, "Invalid argument, %s.\n", tgt);
            return -1;
        } else {
            if (tgt[0] == 'p') {
                if (!sscanf(tgt, "p%d", &target_pid[c])) {
                    fprintf(stderr, "Not a valid integer, %s.\n", tgt+1);
                    return -1;
                }
                target[c] = NULL;
            } else if (tgt[0] == 'm') {
                if (eventType[c] != PROC_EVENT_EXEC) {
                    fprintf(stderr, "Combination of event type %x and %c not supported at the moment.\n", eventType[c], tgt[0]);
                    return -1;
                }
                target[c] = tgt + 1;
            } else {
                // unreachable
            }
        }
        action[c] = argv[3*c + optind + 2];
    }

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) {
        fprintf(stderr, "Error setting output line buffering.\n");
        return -1;
    }

    int rc = runMain();

    free(eventType);
    free(target_pid);
    free(target);
    free(action);

    return rc;
}
