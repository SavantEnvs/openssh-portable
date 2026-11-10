/*
 * sftp_ls_fuzz: the sftp client's `ls` command against a scripted SFTP server.
 *
 * The harness compiles sftp.c (the client's command layer, via build.sh's copy sftp_unit.c) and sftp-usergroup.c into this translation unit,
 * connects the real sftp-client.c protocol code to a server thread over a socketpair, and runs one `ls`
 * command line through the client's own parse_dispatch_command(). The input drives both sides:
 *
 *   byte 0      ls options: bit0 -l, bit1 -n, bit2 -S, bit3 -t, bit4 -r, bit5 -a, bit6 -h,
 *               bit7 the server advertises users-groups-by-id@openssh.com
 *   byte 1      length of the remote path/glob (mod 24)
 *   next bytes  the remote path/glob, each byte picking a character of GLOBCHARS
 *   rest        the server's decisions: directory entry names, whether each lstat/stat succeeds or fails,
 *               and the attributes it returns
 *
 * The server only emits well-formed SFTP replies, so nothing here steers the client into its fatal() paths.
 */
#include "includes.h"

#include <pthread.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "atomicio.h"

#define main sftp_main
#include "sftp_unit.c"
#undef main

#define GLOBCHARS "/abcd*?[]{},."

static const char *const ENTRY_NAMES[] = { "a", "b", "c", "d", "ab", "a.b" };

struct script {
	const uint8_t *p;
	size_t n;
};

static uint8_t
rd(struct script *s)
{
	if (s->n == 0)
		return 0;
	s->n--;
	return *s->p++;
}

struct server {
	int fd;
	int ext_usergroups;
	int listed;
	struct script s;
};

static void
put_attrs(struct sshbuf *m, struct script *s, int want_dir)
{
	uint32_t perm = (want_dir ? S_IFDIR | 0755 : S_IFREG | 0644);

	sshbuf_put_u32(m, SSH2_FILEXFER_ATTR_SIZE | SSH2_FILEXFER_ATTR_UIDGID |
	    SSH2_FILEXFER_ATTR_PERMISSIONS | SSH2_FILEXFER_ATTR_ACMODTIME);
	sshbuf_put_u64(m, rd(s));
	sshbuf_put_u32(m, rd(s) & 3);
	sshbuf_put_u32(m, rd(s) & 3);
	sshbuf_put_u32(m, perm);
	sshbuf_put_u32(m, rd(s));
	sshbuf_put_u32(m, rd(s));
}

static void
send_reply(int fd, struct sshbuf *m)
{
	u_char len[4];
	struct iovec iov[2];

	put_u32(len, sshbuf_len(m));
	iov[0].iov_base = len;
	iov[0].iov_len = sizeof(len);
	iov[1].iov_base = (void *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);
	(void)atomiciov6(writev, fd, iov, 2, NULL, NULL);
}

static void
send_status(int fd, uint32_t id, uint32_t status)
{
	struct sshbuf *m = sshbuf_new();

	sshbuf_put_u8(m, SSH2_FXP_STATUS);
	sshbuf_put_u32(m, id);
	sshbuf_put_u32(m, status);
	sshbuf_put_cstring(m, "");
	sshbuf_put_cstring(m, "");
	send_reply(fd, m);
	sshbuf_free(m);
}

/* uid/gid lookups: n u32s in each of the two strings, answered with n names in each. */
static void
reply_users_groups(struct server *sv, uint32_t id, struct sshbuf *req)
{
	struct sshbuf *uids = NULL, *gids = NULL, *un = sshbuf_new(), *gn = sshbuf_new(), *m = sshbuf_new();
	size_t i, nu, ng;

	if (sshbuf_get_string_direct(req, NULL, NULL) != 0 ||
	    sshbuf_froms(req, &uids) != 0 || sshbuf_froms(req, &gids) != 0) {
		send_status(sv->fd, id, SSH2_FX_BAD_MESSAGE);
		goto out;
	}
	nu = sshbuf_len(uids) / 4;
	ng = sshbuf_len(gids) / 4;
	for (i = 0; i < nu; i++)
		sshbuf_put_cstring(un, rd(&sv->s) & 1 ? "user" : "");
	for (i = 0; i < ng; i++)
		sshbuf_put_cstring(gn, rd(&sv->s) & 1 ? "group" : "");
	sshbuf_put_u8(m, SSH2_FXP_EXTENDED_REPLY);
	sshbuf_put_u32(m, id);
	sshbuf_put_stringb(m, un);
	sshbuf_put_stringb(m, gn);
	send_reply(sv->fd, m);
 out:
	sshbuf_free(uids);
	sshbuf_free(gids);
	sshbuf_free(un);
	sshbuf_free(gn);
	sshbuf_free(m);
}

static void
serve_one(struct server *sv, u_char type, uint32_t id, struct sshbuf *req)
{
	struct sshbuf *m = sshbuf_new();
	uint8_t d;
	int n, i;

	switch (type) {
	case SSH2_FXP_OPENDIR:
		sv->listed = 0;
		sshbuf_put_u8(m, SSH2_FXP_HANDLE);
		sshbuf_put_u32(m, id);
		sshbuf_put_cstring(m, "h");
		send_reply(sv->fd, m);
		break;
	case SSH2_FXP_READDIR:
		if (sv->listed) {
			send_status(sv->fd, id, SSH2_FX_EOF);
			break;
		}
		sv->listed = 1;
		n = rd(&sv->s) & 7;
		sshbuf_put_u8(m, SSH2_FXP_NAME);
		sshbuf_put_u32(m, id);
		sshbuf_put_u32(m, n);
		for (i = 0; i < n; i++) {
			d = rd(&sv->s);
			sshbuf_put_cstring(m, ENTRY_NAMES[d % 6]);
			sshbuf_put_cstring(m, "-rw-r--r-- 1 u g 0 Jan  1 00:00 f");
			put_attrs(m, &sv->s, d & 0x80);
		}
		send_reply(sv->fd, m);
		break;
	case SSH2_FXP_CLOSE:
		send_status(sv->fd, id, SSH2_FX_OK);
		break;
	case SSH2_FXP_LSTAT:
	case SSH2_FXP_STAT:
		d = rd(&sv->s);
		if (d & 1) {
			send_status(sv->fd, id, SSH2_FX_NO_SUCH_FILE);
			break;
		}
		sshbuf_put_u8(m, SSH2_FXP_ATTRS);
		sshbuf_put_u32(m, id);
		put_attrs(m, &sv->s, d & 2);
		send_reply(sv->fd, m);
		break;
	case SSH2_FXP_EXTENDED:
		reply_users_groups(sv, id, req);
		break;
	default:
		send_status(sv->fd, id, SSH2_FX_OP_UNSUPPORTED);
		break;
	}
	sshbuf_free(m);
}

static void *
server_main(void *arg)
{
	struct server *sv = arg;
	u_char hdr[4], *body;
	uint32_t len, id;
	u_char type;
	struct sshbuf *m;

	for (;;) {
		if (atomicio6(read, sv->fd, hdr, 4, NULL, NULL) != 4)
			break;
		len = get_u32(hdr);
		if (len < 1 || len > 65536)
			break;
		body = malloc(len);
		if (body == NULL || atomicio6(read, sv->fd, body, len, NULL, NULL) != len) {
			free(body);
			break;
		}
		m = sshbuf_new();
		if (m != NULL && sshbuf_put(m, body, len) != 0) {
			sshbuf_free(m);
			m = NULL;
		}
		free(body);
		if (m == NULL || sshbuf_get_u8(m, &type) != 0) {
			sshbuf_free(m);
			break;
		}
		if (type == SSH2_FXP_INIT) {
			struct sshbuf *r = sshbuf_new();

			sshbuf_put_u8(r, SSH2_FXP_VERSION);
			sshbuf_put_u32(r, SSH2_FILEXFER_VERSION);
			if (sv->ext_usergroups) {
				sshbuf_put_cstring(r, "users-groups-by-id@openssh.com");
				sshbuf_put_cstring(r, "1");
			}
			send_reply(sv->fd, r);
			sshbuf_free(r);
		} else if (sshbuf_get_u32(m, &id) == 0)
			serve_one(sv, type, id, m);
		sshbuf_free(m);
	}
	return NULL;
}

void sftp_usergroup_reset(void);

static ssize_t
discard_write(void *cookie, const char *buf, size_t n)
{
	return n;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	cookie_io_functions_t io = { NULL, discard_write, NULL, NULL };

	log_init("sftp_ls_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
	signal(SIGPIPE, SIG_IGN);
	if ((stdout = fopencookie(NULL, "w", io)) == NULL)
		return -1;
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct script in = { data, size };
	struct server sv;
	struct sftp_conn *conn;
	pthread_t th;
	char cmd[96] = "ls", *pwd;
	size_t o = strlen(cmd), plen;
	uint8_t flags = rd(&in);
	int sp[2], i;
	static const char opt[] = "lnStrah";

	for (i = 0; i < 7; i++) {
		if (flags & (1 << i)) {
			cmd[o++] = ' ';
			cmd[o++] = '-';
			cmd[o++] = opt[i];
		}
	}
	cmd[o++] = ' ';
	plen = rd(&in) % 24;
	for (i = 0; i < (int)plen; i++)
		cmd[o++] = GLOBCHARS[rd(&in) % (sizeof(GLOBCHARS) - 1)];
	cmd[o] = '\0';

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return 0;
	memset(&sv, 0, sizeof(sv));
	sv.fd = sp[1];
	sv.ext_usergroups = flags >> 7;
	sv.s = in;
	if (pthread_create(&th, NULL, server_main, &sv) != 0) {
		close(sp[0]);
		close(sp[1]);
		return 0;
	}

	sftp_usergroup_reset();
	sort_flag = 0;
	interrupted = 0;
	if ((conn = sftp_init(sp[0], sp[0], 0, 0, 0)) != NULL) {
		pwd = xstrdup("/");
		(void)parse_dispatch_command(conn, cmd, &pwd, "/", 0, 0);
		free(pwd);
		free(conn);
	}
	close(sp[0]);
	pthread_join(th, NULL);
	close(sp[1]);
	return 0;
}
