#
# Copyright (c) 2016 Kinichiro Inoguchi
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set(
	OPENSSL_SRC
	apps.c
	asn1pars.c
	ca.c
	ciphers.c
	crl.c
	crl2p7.c
	cms.c
	dgst.c
	dh.c
	dhparam.c
	dsa.c
	dsaparam.c
	ec.c
	ecparam.c
	enc.c
	errstr.c
	gendh.c
	gendsa.c
	genpkey.c
	genrsa.c
	ocsp.c
	openssl.c
	passwd.c
	pkcs12.c
	pkcs7.c
	pkcs8.c
	pkey.c
	pkeyparam.c
	pkeyutl.c
	prime.c
	rand.c
	req.c
	rsa.c
	rsautl.c
	s_cb.c
	s_client.c
	s_server.c
	s_socket.c
	s_time.c
	sess_id.c
	smime.c
	speed.c
	ts.c
	verify.c
	version.c
	x509.c
)

if(UNIX)
	set(OPENSSL_SRC ${OPENSSL_SRC} apps_posix.c)
	set(OPENSSL_SRC ${OPENSSL_SRC} certhash.c)
endif()

if(WIN32)
	set(OPENSSL_SRC ${OPENSSL_SRC} apps_win.c)
	set(OPENSSL_SRC ${OPENSSL_SRC} certhash_win.c)
	set(OPENSSL_SRC ${OPENSSL_SRC} compat/poll_win.c)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
	check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)
	if(NOT HAVE_CLOCK_GETTIME)
			set(OPENSSL_SRC ${OPENSSL_SRC} compat/clock_gettime_osx.c)
	endif()
endif()

add_executable(openssl ${OPENSSL_SRC})
target_include_directories(openssl
	PRIVATE
		.
		../../include/compat
	PUBLIC
		../../include
		${CMAKE_BINARY_DIR}/include)
target_link_libraries(openssl ${OPENSSL_LIBS} compat_obj)

if(ENABLE_LIBRESSL_INSTALL)
	install(TARGETS openssl DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(FILES openssl.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif(ENABLE_LIBRESSL_INSTALL)
