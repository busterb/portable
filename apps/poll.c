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
compute_revents(int fd, short events, fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	int rc = 0;

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
		 * Windows uses WSAEFAULT for both resource
		 * allocation failures and arguments not being
		 * contained in the user's address space. So,
		 * we have to choose EFAULT or ENOMEM.
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
		 * poll(2) obviously does not normally set
		 * ENOTSOCK, the only fix would be to replace
		 * select with something like
		 * WaitForMultipleObjects. But the original
		 * select(2) uses in openssl(1) would have
		 * already been broken already if they used
		 * file descriptors with select.
		 */
		errno = ENOTSOCK;
		break;
	}
	return -1;
}


/* Just select(2) wrapper, ignored unsupported flags. */
int
poll(struct pollfd *pfds, nfds_t nfds, int timeout)
{
	nfds_t i;
	int rc;
	fd_set rfds, wfds, efds;
	struct timeval tv;
	struct timeval *ptv;

	if (pfds == NULL || nfds > FD_SETSIZE) {
		errno = EINVAL;
		return -1;
	}

	if (timeout < 0) {
		ptv = NULL;
	} else {
		ptv = &tv;
		ptv->tv_sec = timeout / 1000;
		ptv->tv_usec = (timeout % 1000) * 1000;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	for (i = 0; i < nfds; i++) {
		if (pfds[i].fd < 0)
			continue;

		FD_SET(pfds[i].fd, &efds);

		if (pfds[i].events & (POLLIN | POLLRDNORM | POLLRDBAND))
			FD_SET (pfds[i].fd, &rfds);

		if (pfds[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND))
			FD_SET (pfds[i].fd, &wfds);
	}

	/* Winsock ignores the first parameter. */
	rc = select(0, &rfds, &wfds, &efds, ptv);
	if (rc == SOCKET_ERROR)
		return wsa_select_errno(WSAGetLastError());

	rc = 0;
	for (i = 0; i < nfds; i++) {
		pfds[i].revents = 0;

		if (pfds[i].fd < 0)
			continue;

		pfds[i].revents = compute_revents(pfds[i].fd, pfds[i].events,
			&rfds, &wfds, &efds);

		if (pfds[i].revents)
			rc++;
	}

	return rc;
}

