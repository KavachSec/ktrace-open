#ifndef __NETLINK_H__
#define __NETLINK_H__

#include <linux/netlink.h>
#include <linux/audit.h>

/* Audit message types as of 2.6.29 kernel:
 * 1000 - 1099 are for commanding the audit system
 * 1100 - 1199 user space trusted application messages
 * 1200 - 1299 messages internal to the audit daemon
 * 1300 - 1399 audit event messages
 * 1400 - 1499 kernel SE Linux use
 * 1500 - 1599 AppArmor events
 * 1600 - 1699 kernel crypto events
 * 1700 - 1799 kernel anomaly records
 * 1800 - 1899 kernel integrity labels and related events
 * 1800 - 1999 future kernel use
 * 2001 - 2099 unused (kernel)
 * 2100 - 2199 user space anomaly records
 * 2200 - 2299 user space actions taken in response to anomalies
 * 2300 - 2399 user space generated LSPP events
 * 2400 - 2499 user space crypto events
 * 2500 - 2599 user space virtualization management events
 * 2600 - 2999 future user space (maybe integrity labels and related events)
 */

#define AUDIT_FIRST_USER_MSG    1100    /* First user space message */
#define AUDIT_LAST_USER_MSG     1199    /* Last user space message */
#define AUDIT_USER_AUTH         1100    /* User system access authentication */
#define AUDIT_USER_ACCT         1101    /* User system access authorization */
#define AUDIT_USER_MGMT         1102    /* User acct attribute change */
#define AUDIT_CRED_ACQ          1103    /* User credential acquired */
#define AUDIT_CRED_DISP         1104    /* User credential disposed */
#define AUDIT_USER_START        1105    /* User session start */
#define AUDIT_USER_END          1106    /* User session end */
#define AUDIT_USER_AVC          1107    /* User space avc message */
#define AUDIT_USER_CHAUTHTOK	1108	/* User acct password or pin changed */
#define AUDIT_USER_ERR		1109	/* User acct state error */
#define AUDIT_CRED_REFR         1110    /* User credential refreshed */
#define AUDIT_USYS_CONFIG       1111    /* User space system config change */
#define AUDIT_USER_LOGIN	1112    /* User has logged in */
#define AUDIT_USER_LOGOUT	1113    /* User has logged out */
#define AUDIT_ADD_USER		1114    /* User account added */
#define AUDIT_DEL_USER		1115    /* User account deleted */
#define AUDIT_ADD_GROUP		1116    /* Group account added */
#define AUDIT_DEL_GROUP		1117    /* Group account deleted */
#define AUDIT_DAC_CHECK		1118    /* User space DAC check results */
#define AUDIT_CHGRP_ID		1119    /* User space group ID changed */
#define AUDIT_TEST		1120	/* Used for test success messages */
#define AUDIT_TRUSTED_APP	1121	/* Trusted app msg - freestyle text */
#define AUDIT_USER_SELINUX_ERR	1122	/* SE Linux user space error */
#define AUDIT_USER_CMD		1123	/* User shell command and args */
#define AUDIT_USER_TTY		1124	/* Non-ICANON TTY input meaning */
#define AUDIT_CHUSER_ID		1125	/* Changed user ID supplemental data */
#define AUDIT_GRP_AUTH		1126	/* Authentication for group password */
#define AUDIT_SYSTEM_BOOT	1127	/* System boot */
#define AUDIT_SYSTEM_SHUTDOWN	1128	/* System shutdown */
#define AUDIT_SYSTEM_RUNLEVEL	1129	/* System runlevel change */
#define AUDIT_SERVICE_START	1130	/* Service (daemon) start */
#define AUDIT_SERVICE_STOP	1131	/* Service (daemon) stop */
#define AUDIT_GRP_MGMT		1132	/* Group account attr was modified */
#define AUDIT_GRP_CHAUTHTOK	1133	/* Group acct password or pin changed */
#define AUDIT_MAC_CHECK		1134    /* User space MAC decision results */
#define AUDIT_ACCT_LOCK		1135    /* User's account locked by admin */
#define AUDIT_ACCT_UNLOCK	1136    /* User's account unlocked by admin */
#define AUDIT_USER_DEVICE	1137	/* User space hotplug device changes */
#define AUDIT_SOFTWARE_UPDATE	1138	/* Software update event */

#define AUDIT_FIRST_DAEMON	1200
#define AUDIT_LAST_DAEMON	1299
#define AUDIT_DAEMON_RECONFIG	1204	/* Auditd should reconfigure */
#define AUDIT_DAEMON_ROTATE	1205	/* Auditd should rotate logs */
#define AUDIT_DAEMON_RESUME	1206	/* Auditd should resume logging */
#define AUDIT_DAEMON_ACCEPT	1207    /* Auditd accepted remote connection */
#define AUDIT_DAEMON_CLOSE	1208    /* Auditd closed remote connection */
#define AUDIT_DAEMON_ERR	1209    /* Auditd internal error */

#define AUDIT_FIRST_EVENT	1300
#define AUDIT_LAST_EVENT	1399

#define AUDIT_FIRST_SELINUX	1400
#define AUDIT_LAST_SELINUX	1499

#define AUDIT_FIRST_APPARMOR		1500
#define AUDIT_LAST_APPARMOR		1599
#ifndef AUDIT_AA
#define AUDIT_AA			1500	/* Not upstream yet */
#define AUDIT_APPARMOR_AUDIT		1501
#define AUDIT_APPARMOR_ALLOWED		1502
#define AUDIT_APPARMOR_DENIED		1503
#define AUDIT_APPARMOR_HINT		1504
#define AUDIT_APPARMOR_STATUS		1505
#define AUDIT_APPARMOR_ERROR		1506
#endif

#define AUDIT_FIRST_KERN_CRYPTO_MSG	1600
#define AUDIT_LAST_KERN_CRYPTO_MSG	1699

#define AUDIT_FIRST_KERN_ANOM_MSG	1700
#define AUDIT_LAST_KERN_ANOM_MSG	1799

#define AUDIT_INTEGRITY_FIRST_MSG	1800
#define AUDIT_INTEGRITY_LAST_MSG	1899
#ifndef AUDIT_INTEGRITY_DATA
#define AUDIT_INTEGRITY_DATA		1800 /* Data integrity verification */
#define AUDIT_INTEGRITY_METADATA 	1801 // Metadata integrity verification
#define AUDIT_INTEGRITY_STATUS		1802 /* Integrity enable status */
#define AUDIT_INTEGRITY_HASH		1803 /* Integrity HASH type */
#define AUDIT_INTEGRITY_PCR		1804 /* PCR invalidation msgs */
#define AUDIT_INTEGRITY_RULE		1805 /* Policy rule */
#endif
#ifndef AUDIT_INTEGRITY_EVM_XATTR
#define AUDIT_INTEGRITY_EVM_XATTR	1806 /* New EVM-covered xattr */
#endif

#define AUDIT_FIRST_ANOM_MSG		2100
#define AUDIT_LAST_ANOM_MSG		2199
#define AUDIT_ANOM_LOGIN_FAILURES	2100 // Failed login limit reached
#define AUDIT_ANOM_LOGIN_TIME		2101 // Login attempted at bad time
#define AUDIT_ANOM_LOGIN_SESSIONS	2102 // Max concurrent sessions reached
#define AUDIT_ANOM_LOGIN_ACCT		2103 // Login attempted to watched acct
#define AUDIT_ANOM_LOGIN_LOCATION	2104 // Login from forbidden location
#define AUDIT_ANOM_MAX_DAC		2105 // Max DAC failures reached
#define AUDIT_ANOM_MAX_MAC		2106 // Max MAC failures reached
#define AUDIT_ANOM_AMTU_FAIL		2107 // AMTU failure
#define AUDIT_ANOM_RBAC_FAIL		2108 // RBAC self test failure
#define AUDIT_ANOM_RBAC_INTEGRITY_FAIL	2109 // RBAC file integrity failure
#define AUDIT_ANOM_CRYPTO_FAIL		2110 // Crypto system test failure
#define AUDIT_ANOM_ACCESS_FS		2111 // Access of file or dir
#define AUDIT_ANOM_EXEC			2112 // Execution of file
#define AUDIT_ANOM_MK_EXEC		2113 // Make an executable
#define AUDIT_ANOM_ADD_ACCT		2114 // Adding an acct
#define AUDIT_ANOM_DEL_ACCT		2115 // Deleting an acct
#define AUDIT_ANOM_MOD_ACCT		2116 // Changing an acct
#define AUDIT_ANOM_ROOT_TRANS		2117 // User became root
#define AUDIT_ANOM_LOGIN_SERVICE	2118 // Service acct attempted login

#define AUDIT_FIRST_ANOM_RESP		2200
#define AUDIT_LAST_ANOM_RESP		2299
#define AUDIT_RESP_ANOMALY		2200 /* Anomaly not reacted to */
#define AUDIT_RESP_ALERT		2201 /* Alert email was sent */
#define AUDIT_RESP_KILL_PROC		2202 /* Kill program */
#define AUDIT_RESP_TERM_ACCESS		2203 /* Terminate session */
#define AUDIT_RESP_ACCT_REMOTE		2204 /* Acct locked from remote access*/
#define AUDIT_RESP_ACCT_LOCK_TIMED	2205 /* User acct locked for time */
#define AUDIT_RESP_ACCT_UNLOCK_TIMED	2206 /* User acct unlocked from time */
#define AUDIT_RESP_ACCT_LOCK		2207 /* User acct was locked */
#define AUDIT_RESP_TERM_LOCK		2208 /* Terminal was locked */
#define AUDIT_RESP_SEBOOL		2209 /* Set an SE Linux boolean */
#define AUDIT_RESP_EXEC			2210 /* Execute a script */
#define AUDIT_RESP_SINGLE		2211 /* Go to single user mode */
#define AUDIT_RESP_HALT			2212 /* take the system down */
#define AUDIT_RESP_ORIGIN_BLOCK		2213 /* Address blocked by iptables */
#define AUDIT_RESP_ORIGIN_BLOCK_TIMED	2214 /* Address blocked for time */

#define AUDIT_FIRST_USER_LSPP_MSG	2300
#define AUDIT_LAST_USER_LSPP_MSG	2399
#define AUDIT_USER_ROLE_CHANGE		2300 /* User changed to a new role */
#define AUDIT_ROLE_ASSIGN		2301 /* Admin assigned user to role */
#define AUDIT_ROLE_REMOVE		2302 /* Admin removed user from role */
#define AUDIT_LABEL_OVERRIDE		2303 /* Admin is overriding a label */
#define AUDIT_LABEL_LEVEL_CHANGE	2304 /* Object's level was changed */
#define AUDIT_USER_LABELED_EXPORT	2305 /* Object exported with label */
#define AUDIT_USER_UNLABELED_EXPORT	2306 /* Object exported without label */
#define AUDIT_DEV_ALLOC			2307 /* Device was allocated */
#define AUDIT_DEV_DEALLOC		2308 /* Device was deallocated */
#define AUDIT_FS_RELABEL		2309 /* Filesystem relabeled */
#define AUDIT_USER_MAC_POLICY_LOAD	2310 /* Userspc daemon loaded policy */
#define AUDIT_ROLE_MODIFY		2311 /* Admin modified a role */
#define AUDIT_USER_MAC_CONFIG_CHANGE	2312 /* Change made to MAC policy */

#define AUDIT_FIRST_CRYPTO_MSG		2400
#define AUDIT_CRYPTO_TEST_USER		2400 /* Crypto test results */
#define AUDIT_CRYPTO_PARAM_CHANGE_USER	2401 /* Crypto attribute change */
#define AUDIT_CRYPTO_LOGIN		2402 /* Logged in as crypto officer */
#define AUDIT_CRYPTO_LOGOUT		2403 /* Logged out from crypto */
#define AUDIT_CRYPTO_KEY_USER		2404 /* Create,delete,negotiate */
#define AUDIT_CRYPTO_FAILURE_USER	2405 /* Fail decrypt,encrypt,randomiz */
#define AUDIT_CRYPTO_REPLAY_USER	2406 /* Crypto replay detected */
#define AUDIT_CRYPTO_SESSION		2407 /* Record parameters set during
						TLS session establishment */
#define AUDIT_CRYPTO_IKE_SA		2408 /* Record parameters related to
						IKE SA */
#define AUDIT_CRYPTO_IPSEC_SA		2409 /* Record parameters related to
						IPSEC SA */

#define AUDIT_LAST_CRYPTO_MSG		2499

/* Events for both VMs and container orchestration software */
#define AUDIT_FIRST_VIRT_MSG		2500
#define AUDIT_VIRT_CONTROL		2500 /* Start,Pause,Stop VM/container */
#define AUDIT_VIRT_RESOURCE		2501 /* Resource assignment */
#define AUDIT_VIRT_MACHINE_ID		2502 /* Binding of label to VM/cont */
#define AUDIT_VIRT_INTEGRITY_CHECK	2503 /* Guest integrity results */
#define AUDIT_VIRT_CREATE		2504 /* Creation of guest image */
#define AUDIT_VIRT_DESTROY		2505 /* Destruction of guest image */
#define AUDIT_VIRT_MIGRATE_IN		2506 /* Inbound guest migration info */
#define AUDIT_VIRT_MIGRATE_OUT		2507 /* Outbound guest migration info */

#define AUDIT_LAST_VIRT_MSG		2599

#ifndef AUDIT_FIRST_USER_MSG2
#define AUDIT_FIRST_USER_MSG2  2100    /* More userspace messages */
#define AUDIT_LAST_USER_MSG2   2999
#endif

/* New kernel event definitions since 2.6.30 */
#ifndef AUDIT_SET_FEATURE
#define AUDIT_SET_FEATURE       1018    /* Turn an audit feature on or off */
#endif

#ifndef AUDIT_GET_FEATURE
#define AUDIT_GET_FEATURE       1019    /* Get which features are enabled */
#endif

#ifndef AUDIT_MMAP
#define AUDIT_MMAP		1323 /* Descriptor and flags in mmap */
#endif

#ifndef AUDIT_NETFILTER_PKT
#define AUDIT_NETFILTER_PKT	1324 /* Packets traversing netfilter chains */
#endif
#ifndef AUDIT_NETFILTER_CFG
#define AUDIT_NETFILTER_CFG	1325 /* Netfilter chain modifications */
#endif

#ifndef AUDIT_SECCOMP
#define AUDIT_SECCOMP		1326 /* Secure Computing event */
#endif

#ifndef AUDIT_PROCTITLE
#define AUDIT_PROCTITLE		1327 /* Process Title info */
#endif

#undef AUDIT_FEATURE_CHANGE
#ifndef AUDIT_FEATURE_CHANGE
#define AUDIT_FEATURE_CHANGE	1328 /* Audit feature changed value */
#endif

#ifndef AUDIT_REPLACE
#define AUDIT_REPLACE           1329 /* Auditd replaced because probe failed */
#endif

#ifndef AUDIT_KERN_MODULE
#define AUDIT_KERN_MODULE	1330 /* Kernel Module events */
#endif

#ifndef AUDIT_FANOTIFY
#define AUDIT_FANOTIFY		1331 /* Fanotify access decision */
#endif

#ifndef AUDIT_TIME_INJOFFSET
#define AUDIT_TIME_INJOFFSET	1332 /* Timekeeping offset injected */
#endif

#ifndef AUDIT_TIME_ADJNTPVAL
#define AUDIT_TIME_ADJNTPVAL	1333 /* NTP value adjustment */
#endif

#ifndef AUDIT_MAC_CALIPSO_ADD
#define AUDIT_MAC_CALIPSO_ADD	1418 /* NetLabel: add CALIPSO DOI entry */
#endif

#ifndef AUDIT_MAC_CALIPSO_DEL
#define AUDIT_MAC_CALIPSO_DEL	1419 /* NetLabel: del CALIPSO DOI entry */
#endif

#ifndef AUDIT_ANOM_LINK
#define AUDIT_ANOM_LINK		1702 /* Suspicious use of file links */
#endif

/* This is related to the filterkey patch */
#define AUDIT_KEY_SEPARATOR 0x01

/* These are used in filter control */
#ifndef AUDIT_FILTER_FS
#define AUDIT_FILTER_FS		0x06 /* FS record filter in __audit_inode_child */
#endif
#ifndef AUDIT_FILTER_EXCLUDE
#define AUDIT_FILTER_EXCLUDE	AUDIT_FILTER_TYPE
#endif
#define AUDIT_FILTER_MASK	0x07	/* Mask to get actual filter */
#define AUDIT_FILTER_UNSET	0x80	/* This value means filter is unset */

/* Status symbol mask values */
#ifndef AUDIT_STATUS_LOST
#define AUDIT_STATUS_LOST               0x0040
#endif

/* These defines describe what features are in the kernel */
#ifndef AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT
#define AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT      0x00000001
#endif
#ifndef AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME
#define AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME  0x00000002
#endif
#ifndef AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH
#define AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH    0x00000004
#endif
#ifndef AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND
#define AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND     0x00000008
#endif
#ifndef AUDIT_FEATURE_BITMAP_SESSIONID_FILTER
#define AUDIT_FEATURE_BITMAP_SESSIONID_FILTER   0x00000010
#endif
#ifndef AUDIT_FEATURE_BITMAP_LOST_RESET
#define AUDIT_FEATURE_BITMAP_LOST_RESET		0x00000020
#endif
#ifndef AUDIT_FEATURE_BITMAP_FILTER_FS
#define AUDIT_FEATURE_BITMAP_FILTER_FS		0x00000040
#endif

/* Defines for interfield comparison update */
#ifndef AUDIT_OBJ_UID
#define AUDIT_OBJ_UID  109
#endif
#ifndef AUDIT_OBJ_GID
#define AUDIT_OBJ_GID  110
#endif
#ifndef AUDIT_FIELD_COMPARE
#define AUDIT_FIELD_COMPARE 111
#endif
#ifndef AUDIT_EXE
#define AUDIT_EXE 112
#endif
#ifndef AUDIT_SADDR_FAM
#define AUDIT_SADDR_FAM 113
#endif

#ifndef AUDIT_SESSIONID
#define AUDIT_SESSIONID 25
#endif

#ifndef AUDIT_FSTYPE
#define AUDIT_FSTYPE 26
#endif

#ifndef AUDIT_COMPARE_UID_TO_OBJ_UID
#define AUDIT_COMPARE_UID_TO_OBJ_UID   1
#endif
#ifndef AUDIT_COMPARE_GID_TO_OBJ_GID
#define AUDIT_COMPARE_GID_TO_OBJ_GID   2
#endif
#ifndef AUDIT_COMPARE_EUID_TO_OBJ_UID
#define AUDIT_COMPARE_EUID_TO_OBJ_UID  3
#endif
#ifndef AUDIT_COMPARE_EGID_TO_OBJ_GID
#define AUDIT_COMPARE_EGID_TO_OBJ_GID  4
#endif
#ifndef AUDIT_COMPARE_AUID_TO_OBJ_UID
#define AUDIT_COMPARE_AUID_TO_OBJ_UID  5
#endif
#ifndef AUDIT_COMPARE_SUID_TO_OBJ_UID
#define AUDIT_COMPARE_SUID_TO_OBJ_UID  6
#endif
#ifndef AUDIT_COMPARE_SGID_TO_OBJ_GID
#define AUDIT_COMPARE_SGID_TO_OBJ_GID  7
#endif
#ifndef AUDIT_COMPARE_FSUID_TO_OBJ_UID
#define AUDIT_COMPARE_FSUID_TO_OBJ_UID 8
#endif
#ifndef AUDIT_COMPARE_FSGID_TO_OBJ_GID
#define AUDIT_COMPARE_FSGID_TO_OBJ_GID 9
#endif
#ifndef AUDIT_COMPARE_UID_TO_AUID
#define AUDIT_COMPARE_UID_TO_AUID      10
#endif
#ifndef AUDIT_COMPARE_UID_TO_EUID
#define AUDIT_COMPARE_UID_TO_EUID      11
#endif
#ifndef AUDIT_COMPARE_UID_TO_FSUID
#define AUDIT_COMPARE_UID_TO_FSUID     12
#endif
#ifndef AUDIT_COMPARE_UID_TO_SUID
#define AUDIT_COMPARE_UID_TO_SUID      13
#endif
#ifndef AUDIT_COMPARE_AUID_TO_FSUID
#define AUDIT_COMPARE_AUID_TO_FSUID    14
#endif
#ifndef AUDIT_COMPARE_AUID_TO_SUID
#define AUDIT_COMPARE_AUID_TO_SUID     15
#endif
#ifndef AUDIT_COMPARE_AUID_TO_EUID
#define AUDIT_COMPARE_AUID_TO_EUID     16
#endif
#ifndef AUDIT_COMPARE_EUID_TO_SUID
#define AUDIT_COMPARE_EUID_TO_SUID     17
#endif
#ifndef AUDIT_COMPARE_EUID_TO_FSUID
#define AUDIT_COMPARE_EUID_TO_FSUID    18
#endif
#ifndef AUDIT_COMPARE_SUID_TO_FSUID
#define AUDIT_COMPARE_SUID_TO_FSUID    19
#endif
#ifndef AUDIT_COMPARE_GID_TO_EGID
#define AUDIT_COMPARE_GID_TO_EGID      20
#endif
#ifndef AUDIT_COMPARE_GID_TO_FSGID
#define AUDIT_COMPARE_GID_TO_FSGID     21
#endif
#ifndef AUDIT_COMPARE_GID_TO_SGID
#define AUDIT_COMPARE_GID_TO_SGID      22
#endif
#ifndef AUDIT_COMPARE_EGID_TO_FSGID
#define AUDIT_COMPARE_EGID_TO_FSGID    23
#endif
#ifndef AUDIT_COMPARE_EGID_TO_SGID
#define AUDIT_COMPARE_EGID_TO_SGID     24
#endif
#ifndef AUDIT_COMPARE_SGID_TO_FSGID
#define AUDIT_COMPARE_SGID_TO_FSGID    25
#endif

#ifndef EM_ARM
#define EM_ARM  40
#endif
#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif

#ifndef AUDIT_ARCH_PPC64LE
#define AUDIT_ARCH_PPC64LE	(EM_PPC64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif

/* This is the character that separates event data from enrichment fields */
#define AUDIT_INTERP_SEPARATOR 0x1D

//////////////////////////////////////////////////////
// This is an external ABI. Any changes in here will
// likely affect pam_loginuid. There might be other
// apps that use this low level interface, but I don't
// know of any.
//
/* data structure for who signaled the audit daemon */
struct audit_sig_info {
        uid_t           uid;
        pid_t           pid;
	char		ctx[0];
};

/* defines for audit subsystem */
#define MAX_AUDIT_MESSAGE_LENGTH    8970 // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1
struct audit_message {
	struct nlmsghdr nlh;
	char   data[MAX_AUDIT_MESSAGE_LENGTH];
};

// internal - forward declaration
struct daemon_conf;

struct audit_reply {
	int                      type;
	int                      len;
	struct nlmsghdr         *nlh;
	struct audit_message     msg;

	/* Using a union to compress this structure since only one of
	 * the following should be valid for any packet. */
	union {
	struct audit_status     *status;
	struct audit_rule_data  *ruledata;
	struct audit_login      *login;
	char                    *message;
	struct nlmsgerr         *error;
	struct audit_sig_info   *signal_info;
	struct daemon_conf      *conf;
#ifdef AUDIT_FEATURE_BITMAP_ALL
	struct audit_features	*features;
#endif
	};
};

typedef enum { GET_REPLY_BLOCKING=0, GET_REPLY_NONBLOCKING } reply_t;
//static struct auditd_event *cur_event = NULL,*reconfig_ev = NULL;

typedef void (*ack_func_type)(void *ack_data, const unsigned char *header, const char *msg);
struct auditd_event {
        struct audit_reply reply;
        ack_func_type ack_func;
        void *ack_data;
        unsigned long sequence_id;
};

#define DEFAULT_BUF_SZ  448
#define FORMAT_BUF_LEN (MAX_AUDIT_MESSAGE_LENGTH + _POSIX_HOST_NAME_MAX)
#define SUBJ_LEN 4097
#define DMSG_SIZE (DEFAULT_BUF_SZ + 48)


int audit_open(void);
void audit_close(int fd);
//void netlink_handler(struct ev_loop *loop, struct ev_io *io, int revents);
int audit_send(int fd, int type, const void *data, unsigned int size);
int audit_get_reply(int fd, struct audit_reply *rep, reply_t block, int peek);
#endif
