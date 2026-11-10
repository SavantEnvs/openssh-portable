/*
 * sftp-usergroup.c plus a reset of its uid/gid-to-name caches, which the harness calls before every input so
 * that one input's server replies cannot change what the next one does.
 */
#include "sftp-usergroup.c"

void
sftp_usergroup_reset(void)
{
	struct idname *n;

	while ((n = RB_MIN(idname_tree, &user_idname)) != NULL) {
		RB_REMOVE(idname_tree, &user_idname, n);
		idname_free(n);
	}
	while ((n = RB_MIN(idname_tree, &group_idname)) != NULL) {
		RB_REMOVE(idname_tree, &group_idname, n);
		idname_free(n);
	}
}
