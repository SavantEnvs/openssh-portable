/* File-input driver for the ssh client configuration parser (readconf.c: read_config_file()). Same code
 * path as upstream's regress/misc/fuzz-harness/sshconfig_fuzz.cc, but as a file-input target: readconf
 * calls fatal() (exit 255) on any bad option, which a libFuzzer harness would report as a crash on
 * nearly every mutation, and the fleet rules forbid longjmp/--wrap shims to survive that. */
#include "includes.h"

#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include "ssh.h"
#include "misc.h"
#include "log.h"
#include "readconf.h"

int
main(int argc, char **argv)
{
	static char name[] = "fuzzer", home[] = "/tmp", shell[] = "/bin/sh";
	struct passwd pw;
	Options options;

	if (argc != 2)
		return 2;
	/* `Match exec` runs its argument with $SHELL: point it at a missing shell so that never executes. */
	setenv("SHELL", "/nonexistent-shell", 1);
	log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
	pw.pw_name = name;
	pw.pw_uid = getuid();
	pw.pw_gid = getgid();
	pw.pw_dir = home;
	pw.pw_shell = shell;
	initialize_options(&options);
	read_config_file(argv[1], &pw, "fuzz.example.com", "fuzz.example.com",
	    NULL, &options, 0, NULL);
	return 0;
}
