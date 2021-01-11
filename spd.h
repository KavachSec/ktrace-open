#ifndef __SPD_H__
#define __SPD_H__

#ifdef __cplusplus
extern "C" {
#endif

int start_auditd_thread(void);
int wait_for_audit_thread_to_terminate(void);

#ifdef __cplusplus
}
#endif

#endif //__SPD_H__
