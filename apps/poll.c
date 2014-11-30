/*
 * Public domain
 *
 * poll(2) emulation for Windows
 *
 * This emulates just-enough poll functionality on Windows to work in the
 * context of the openssl(1) program. This is not a replacement for
 * POSIX.1-2001 poll(2).
 *
 * Dongsheng Song <dongsheng.song@gmail.com>
 * Brent Cook <bcook@openbsd.org>
 */

#include <io.h>
#include <ws2tcpip.h>

#include <errno.h>
#include <poll.h>

static int
conn_is_closed(int fd)
{
	char buf[1];
	int ret = recv(fd, buf, 1, MSG_PEEK);
	if (ret == -1) {
		switch (WSAGetLastError()) {
		case WSAECONNABORTED:
		case WSAECONNRESET:
		case WSAENETRESET:
		case WSAESHUTDOWN:
			return 1;
		}
	}
	return 0;
}

static int
conn_has_oob_data(int fd)
{
	char buf[1];
	return (recv(fd, buf, 1, MSG_PEEK | MSG_OOB) == 1);
}

static int
is_socket(int fd)
{
	WSANETWORKEVENTS events;
	return (WSAEnumNetworkEvents((SOCKET)fd, NULL, &events) == 0);
}

static int
compute_revents(int fd, short events, fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	int rc = 0;

	if (is_socket(fd)) {
		if ((events & (POLLIN | POLLRDNORM | POLLRDBAND)) &&
				FD_ISSET(fd, rfds)) {
			if (conn_is_closed(fd))
				rc |= POLLHUP;
			else
				rc |= POLLIN | POLLRDNORM;
		}

		if ((events & (POLLOUT | POLLWRNORM | POLLWRBAND)) &&
				FD_ISSET(fd, wfds))
			rc |= POLLOUT;

		if (FD_ISSET(fd, efds)) {
			if (conn_is_closed(fd))
				rc |= POLLHUP;
			else if (conn_has_oob_data(fd))
				rc |= POLLRDBAND | POLLPRI;
		}

	}

	return rc;
}

static int
compute_wait_revents(short events, int object, int wait_rc)
{
	int rc = 0;

	if (events & (POLLOUT | POLLWRNORM))
		rc |= POLLOUT;

	if (wait_rc >= WAIT_OBJECT_0 && (object == (wait_rc - WAIT_OBJECT_0))) {
		if (events & (POLLIN | POLLRDNORM))
			rc |= POLLIN;
	}

	return rc;
}

static int
wsa_select_errno(int err)
{
	switch (err) {
	case WSAEINTR:
	case WSAEINPROGRESS:
		errno = EINTR;
		break;
	case WSAEFAULT:
		/*
		 * Windows uses WSAEFAULT for both resource allocation failures
		 * and arguments not being contained in the user's address
		 * space. So, we have to choose EFAULT or ENOMEM.
		 */
		errno = EFAULT;
		break;
	case WSAEINVAL:
		errno = EINVAL;
		break;
	case WSANOTINITIALISED:
		errno = EPERM;
		break;
	case WSAENETDOWN:
		errno = ENOMEM;
		break;
	case WSAENOTSOCK:
		/*
		 * poll(2) obviously does not normally set ENOTSOCK, the only
		 * fix would be to replace select with something like
		 * WaitForMultipleObjects. But the original select(2) uses in
		 * openssl(1) would have already been broken already if they
		 * used file descriptors with select.
		 */
		errno = ENOTSOCK;
		break;
	}
	return -1;
}

int
poll(struct pollfd *pfds, nfds_t nfds, int timeout_ms)
{
	nfds_t i;
	int timespent_ms, looptime_ms;

	/*
	 * select machinery
	 */
	fd_set rfds, wfds, efds;
	int rc;
	int num_sockets = 0;

	/*
	 * wait machinery
	 */
	DWORD wait_rc = 0;
	HANDLE handles[FD_SETSIZE];
	int num_handles = 0;

	if (pfds == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (nfds <= 0) {
		return 0;
	}

	if (timeout_ms < 0) {
		timeout_ms = INFINITE;
	}
	looptime_ms = timeout_ms > 100 ? 100 : timeout_ms;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	for (i = 0; i < nfds; i++) {
		if ((int)pfds[i].fd < 0) {
			continue;
		}

		if (is_socket(pfds[i].fd)) {
			if (num_sockets >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			FD_SET(pfds[i].fd, &efds);

			if (pfds[i].events & (POLLIN | POLLRDNORM | POLLRDBAND)) {
				FD_SET(pfds[i].fd, &rfds);
			}

			if (pfds[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
				FD_SET(pfds[i].fd, &wfds);
			}
			num_sockets++;

		} else {
			if (num_handles >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			handles[num_handles++] = (HANDLE)_get_osfhandle(pfds[i].fd);
		}
	}

	timespent_ms = 0;
	do {
		struct timeval tv = {0, looptime_ms * 1000};

		if (num_handles) {
			wait_rc = WaitForMultipleObjects(num_handles, handles, FALSE, 0);
			if (wait_rc == WAIT_FAILED) {
				return 0;
			}
		}

		rc = select(0, &rfds, &wfds, &efds, &tv);
		if (rc == SOCKET_ERROR) {
			return wsa_select_errno(WSAGetLastError());
		}

		timespent_ms += looptime_ms;
	} while (timespent_ms < timeout_ms);

	rc = 0;
	num_handles = 0;
	for (i = 0; i < nfds; i++) {
		pfds[i].revents = 0;

		if ((int)pfds[i].fd < 0)
			continue;

		if (is_socket(pfds[i].fd)) {
			pfds[i].revents = compute_revents(pfds[i].fd,
			    pfds[i].events, &rfds, &wfds, &efds);

		} else {
			pfds[i].revents = compute_wait_revents(pfds[i].events,
			    num_handles++, wait_rc);
		}
		if (pfds[i].revents)
			rc++;
	}

	return rc;
}

