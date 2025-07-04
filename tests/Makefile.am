#
# Copyright (c) 2015 Brent Cook
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

include $(top_srcdir)/Makefile.am.common

-include $(abs_top_builddir)/crypto/libcrypto_la_objects.mk
-include $(abs_top_builddir)/ssl/libssl_la_objects.mk
-include $(abs_top_builddir)/tls/libtls_la_objects.mk

AM_CPPFLAGS += -DLIBRESSL_CRYPTO_INTERNAL

AM_CPPFLAGS += -I $(top_srcdir)/crypto/
AM_CPPFLAGS += -I $(top_srcdir)/crypto/asn1
AM_CPPFLAGS += -I $(top_srcdir)/crypto/bio
AM_CPPFLAGS += -I $(top_srcdir)/crypto/bn
AM_CPPFLAGS += -I $(top_srcdir)/crypto/bytestring
AM_CPPFLAGS += -I $(top_srcdir)/crypto/curve25519
AM_CPPFLAGS += -I $(top_srcdir)/crypto/ec
AM_CPPFLAGS += -I $(top_srcdir)/crypto/evp
AM_CPPFLAGS += -I $(top_srcdir)/crypto/mlkem
AM_CPPFLAGS += -I $(top_srcdir)/crypto/modes
AM_CPPFLAGS += -I $(top_srcdir)/crypto/sha
AM_CPPFLAGS += -I $(top_srcdir)/crypto/x509
AM_CPPFLAGS += -I $(top_srcdir)/ssl
AM_CPPFLAGS += -I $(top_srcdir)/tests
AM_CPPFLAGS += -I $(top_srcdir)/apps/openssl
AM_CPPFLAGS += -I $(top_srcdir)/apps/openssl/compat
AM_CPPFLAGS += -D_PATH_SSL_CA_FILE=\"$(top_srcdir)/cert.pem\"

# arch
if HOST_AARCH64
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/aarch64/
endif

if HOST_ARM
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/arm/
endif

if HOST_I386
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/i386/
endif

if HOST_LOONGARCH64
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/loongarch64/
endif

if HOST_MIPS
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/mips/
endif

if HOST_MIPS64
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/mips64/
endif

if HOST_POWERPC
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/powerpc/
endif

if HOST_POWERPC64
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/powerpc64/
endif

if HOST_RISCV64
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/riscv64/
endif

if HOST_SPARC64
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/sparc64/
endif

if HOST_X86_64
AM_CPPFLAGS += -I$(top_srcdir)/crypto/arch/amd64/
endif

noinst_LTLIBRARIES = libtest.la
libtest_la_LIBADD = $(libcrypto_la_objects)
libtest_la_LIBADD += $(libcompat_la_objects)
libtest_la_LIBADD += $(libcompatnoopt_la_objects)
libtest_la_LIBADD += $(libssl_la_objects)
libtest_la_LIBADD += $(libtls_la_objects)
libtest_la_SOURCES = empty.c

LDADD = libtest.la $(PLATFORM_LDADD) $(PROG_LDADD)

TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/tap-driver.sh

TESTS =
XFAIL_TESTS =
check_PROGRAMS =
EXTRA_DIST = CMakeLists.txt
DISTCLEANFILES = pidwraptest.txt

# XXX - should probably be in their own static lib
TEST_HELPER_SRC = test.c test_util.c
noinst_HEADERS = test.h
EXTRA_DIST += $(TEST_HELPER_SRC)

# aeadtest
TESTS += aeadtest.sh
check_PROGRAMS += aeadtest
aeadtest_SOURCES = aeadtest.c
EXTRA_DIST += aeadtest.sh
EXTRA_DIST += aeadtests.txt
EXTRA_DIST += aes_128_gcm_tests.txt
EXTRA_DIST += aes_192_gcm_tests.txt
EXTRA_DIST += aes_256_gcm_tests.txt
EXTRA_DIST += chacha20_poly1305_tests.txt
EXTRA_DIST += xchacha20_poly1305_tests.txt

# aes
TESTS += aes_test
check_PROGRAMS += aes_test
aes_test_SOURCES = aes_test.c

# aes_wrap
TESTS += aes_wrap
check_PROGRAMS += aes_wrap
aes_wrap_SOURCES = aes_wrap.c

# apitest
TESTS += apitest
check_PROGRAMS += apitest
apitest_SOURCES = apitest.c
apitest_CPPFLAGS = $(AM_CPPFLAGS) -DCERTSDIR=\"$(srcdir)\"

# arc4randomforktest
# Windows/mingw does not have fork, but Cygwin does.
if !HOST_WIN
TESTS += arc4randomforktest.sh
check_PROGRAMS += arc4randomforktest
arc4randomforktest_SOURCES = arc4randomforktest.c
endif
EXTRA_DIST += arc4randomforktest.sh

# asn1_string_to_utf8
TESTS += asn1_string_to_utf8
check_PROGRAMS += asn1_string_to_utf8
asn1_string_to_utf8_SOURCES = asn1_string_to_utf8.c

# asn1api
TESTS += asn1api
check_PROGRAMS += asn1api
asn1api_SOURCES = asn1api.c

# asn1basic
TESTS += asn1basic
check_PROGRAMS += asn1basic
asn1basic_SOURCES = asn1basic.c

# asn1complex
TESTS += asn1complex
check_PROGRAMS += asn1complex
asn1complex_SOURCES = asn1complex.c

# asn1evp
TESTS += asn1evp
check_PROGRAMS += asn1evp
asn1evp_SOURCES = asn1evp.c

# asn1object
TESTS += asn1object
check_PROGRAMS += asn1object
asn1object_SOURCES = asn1object.c

# asn1oct
TESTS += asn1oct
check_PROGRAMS += asn1oct
asn1oct_SOURCES = asn1oct.c

# asn1string_copy
TESTS += asn1string_copy
check_PROGRAMS += asn1string_copy
asn1string_copy_SOURCES = asn1string_copy.c

# asn1test
TESTS += asn1test
check_PROGRAMS += asn1test
asn1test_SOURCES = asn1test.c

# asn1time
check_PROGRAMS += asn1time
asn1time_SOURCES = asn1time.c
if SMALL_TIME_T
TESTS += asn1time_small.test
XFAIL_TESTS += asn1time_small.test
else
TESTS += asn1time
endif
EXTRA_DIST += asn1time_small.test

# asn1x509
TESTS += asn1x509
check_PROGRAMS += asn1x509
asn1x509_SOURCES = asn1x509.c

# base64test
TESTS += base64test
check_PROGRAMS += base64test
base64test_SOURCES = base64test.c

# bf_test
TESTS += bf_test
check_PROGRAMS += bf_test
bf_test_SOURCES = bf_test.c

# bio_asn1
TESTS += bio_asn1
check_PROGRAMS += bio_asn1
bio_asn1_SOURCES = bio_asn1.c

# bio_chain
TESTS += bio_chain
check_PROGRAMS += bio_chain
bio_chain_SOURCES = bio_chain.c

# bio_dump
TESTS += bio_dump
check_PROGRAMS += bio_dump
bio_dump_SOURCES = bio_dump.c

# bio_host
# this test relies on resolver results that are OS and environment-specific
if ENABLE_EXTRATESTS
TESTS += bio_host
check_PROGRAMS += bio_host
bio_host_SOURCES = bio_host.c
endif

# bio_mem
TESTS += bio_mem
check_PROGRAMS += bio_mem
bio_mem_SOURCES = bio_mem.c

# bn_add_sub
TESTS += bn_add_sub
check_PROGRAMS += bn_add_sub
bn_add_sub_SOURCES = bn_add_sub.c

# bn_bits
TESTS += bn_bits
check_PROGRAMS += bn_bits
bn_bits_SOURCES = bn_bits.c

# bn_cmp
TESTS += bn_cmp
check_PROGRAMS += bn_cmp
bn_cmp_SOURCES = bn_cmp.c

# bn_convert
TESTS += bn_convert
check_PROGRAMS += bn_convert
bn_convert_SOURCES = bn_convert.c

# bn_gcd
TESTS += bn_gcd
check_PROGRAMS += bn_gcd
bn_gcd_SOURCES = bn_gcd.c

# bn_general is a benchmark.

# bn_isqrt
TESTS += bn_isqrt
check_PROGRAMS += bn_isqrt
bn_isqrt_SOURCES = bn_isqrt.c

# bn_mod_exp
TESTS += bn_mod_exp
check_PROGRAMS += bn_mod_exp
bn_mod_exp_CPPFLAGS = $(AM_CPPFLAGS) -ULIBRESSL_INTERNAL
bn_mod_exp_SOURCES = bn_mod_exp.c

# bn_mod_inverse
TESTS += bn_mod_inverse
check_PROGRAMS += bn_mod_inverse
bn_mod_inverse_SOURCES = bn_mod_inverse.c

# bn_mod_sqrt
TESTS += bn_mod_sqrt
check_PROGRAMS += bn_mod_sqrt
bn_mod_sqrt_SOURCES = bn_mod_sqrt.c

# bn_mont
TESTS += bn_mont
check_PROGRAMS += bn_mont
bn_mont_SOURCES = bn_mont.c

# bn_primes
TESTS += bn_primes
check_PROGRAMS += bn_primes
bn_primes_SOURCES = bn_primes.c

# bn_print
TESTS += bn_print
check_PROGRAMS += bn_print
bn_print_SOURCES = bn_print.c

# bn_shift
TESTS += bn_shift
check_PROGRAMS += bn_shift
bn_shift_SOURCES = bn_shift.c

# bn_test
TESTS += bn_test
bn_test_CPPFLAGS = $(AM_CPPFLAGS) -ULIBRESSL_INTERNAL
check_PROGRAMS += bn_test
bn_test_SOURCES = bn_test.c

# bn_to_string
TESTS += bn_to_string
check_PROGRAMS += bn_to_string
bn_to_string_SOURCES = bn_to_string.c

# bn_unit
TESTS += bn_unit
check_PROGRAMS += bn_unit
bn_unit_SOURCES = bn_unit.c

# bn_word
TESTS += bn_word
check_PROGRAMS += bn_word
bn_word_SOURCES = bn_word.c

# buffertest
TESTS += buffertest
check_PROGRAMS += buffertest
buffertest_SOURCES = buffertest.c

# bytestringtest
TESTS += bytestringtest
check_PROGRAMS += bytestringtest
bytestringtest_SOURCES = bytestringtest.c

# callback
# callbackfailures

# casttest
TESTS += casttest
check_PROGRAMS += casttest
casttest_SOURCES = casttest.c

# chachatest
TESTS += chachatest
check_PROGRAMS += chachatest
chachatest_SOURCES = chachatest.c

# cipher_list
TESTS += cipher_list
check_PROGRAMS += cipher_list
cipher_list_SOURCES = cipher_list.c
noinst_HEADERS += tests.h

# cipherstest
TESTS += cipherstest
check_PROGRAMS += cipherstest
cipherstest_SOURCES = cipherstest.c

## clienttest
TESTS += clienttest
check_PROGRAMS += clienttest
clienttest_SOURCES = clienttest.c

# cmstest
TESTS += cmstest
check_PROGRAMS += cmstest
cmstest_SOURCES = cmstest.c

# configtest
TESTS += configtest
check_PROGRAMS += configtest
configtest_SOURCES = configtest.c

# constraints
TESTS += constraints
check_PROGRAMS += constraints
constraints_SOURCES = constraints.c

# crypto_test
TESTS += crypto_test
check_PROGRAMS += crypto_test
crypto_test_SOURCES = crypto_test.c

# cttest
TESTS += cttest
check_PROGRAMS += cttest
cttest_SOURCES = cttest.c
cttest_CPPFLAGS = $(AM_CPPFLAGS) -DCTPATH=\"$(srcdir)\"
EXTRA_DIST += ctlog.conf
EXTRA_DIST += letsencrypt-r3.crt
EXTRA_DIST += libressl.org.crt

# destest
TESTS += destest
check_PROGRAMS += destest
destest_SOURCES = destest.c

# dhtest
TESTS += dhtest
check_PROGRAMS += dhtest
dhtest_SOURCES = dhtest.c

# dsatest
TESTS += dsatest
check_PROGRAMS += dsatest
dsatest_SOURCES = dsatest.c

# XXX this test is too flaky for CI. Disable it until it is fixed.
## dtlstest
#if !HOST_WIN
#TESTS += dtlstest.sh
#check_PROGRAMS += dtlstest
#dtlstest_SOURCES = dtlstest.c
#endif
#EXTRA_DIST += dtlstest.sh

# ecc_cdh
TESTS += ecc_cdh
check_PROGRAMS += ecc_cdh
ecc_cdh_SOURCES = ecc_cdh.c

# ec_asn1_test
TESTS += ec_asn1_test
check_PROGRAMS += ec_asn1_test
ec_asn1_test_SOURCES = ec_asn1_test.c

# ec_point_conversion
TESTS += ec_point_conversion
check_PROGRAMS += ec_point_conversion
ec_point_conversion_SOURCES = ec_point_conversion.c

# ecdhtest
TESTS += ecdhtest
check_PROGRAMS += ecdhtest
ecdhtest_SOURCES = ecdhtest.c

# ecdsatest
TESTS += ecdsatest
check_PROGRAMS += ecdsatest
ecdsatest_SOURCES = ecdsatest.c

# ectest
TESTS += ectest
check_PROGRAMS += ectest
ectest_SOURCES = ectest.c

# ed25519test
TESTS += ed25519test
check_PROGRAMS += ed25519test
ed25519test_SOURCES = ed25519test.c

# err_test
TESTS += err_test
check_PROGRAMS += err_test
err_test_SOURCES = err_test.c

# evp_ecx_test
TESTS += evp_ecx_test
check_PROGRAMS += evp_ecx_test
evp_ecx_test_SOURCES = evp_ecx_test.c

# evp_pkey_cleanup
TESTS += evp_pkey_cleanup
check_PROGRAMS += evp_pkey_cleanup
evp_pkey_cleanup_SOURCES = evp_pkey_cleanup.c

# evptest
TESTS += evptest.sh
check_PROGRAMS += evptest
evptest_SOURCES = evptest.c
EXTRA_DIST += evptest.sh
EXTRA_DIST += evptests.txt

# evp_test
TESTS += evp_test
check_PROGRAMS += evp_test
evp_test_SOURCES = evp_test.c

# exdata_test
TESTS += exdata_test
check_PROGRAMS += exdata_test
exdata_test_SOURCES = exdata_test.c

# expirecallback.c

# explicit_bzero
# explicit_bzero relies on SA_ONSTACK, which is unavailable on Windows
if !HOST_WIN
if !HOST_CYGWIN
TESTS += explicit_bzero
check_PROGRAMS += explicit_bzero
explicit_bzero_SOURCES = explicit_bzero.c
if !HAVE_MEMMEM
explicit_bzero_SOURCES += compat/memmem.c
endif
endif
endif

# exportertest
TESTS += exportertest
check_PROGRAMS += exportertest
exportertest_SOURCES = exportertest.c

# freenull
TESTS += freenull
freenull_CPPFLAGS = $(AM_CPPFLAGS) -ULIBRESSL_INTERNAL
check_PROGRAMS += freenull
freenull_SOURCES = freenull.c

# gcm128test
TESTS += gcm128test
check_PROGRAMS += gcm128test
gcm128test_SOURCES = gcm128test.c

# handshake_table
TESTS += handshake_table
check_PROGRAMS += handshake_table
handshake_table_SOURCES = handshake_table.c

# hkdf_test
TESTS += hkdftest
check_PROGRAMS += hkdftest
hkdftest_SOURCES = hkdf_test.c

# hmactest
TESTS += hmactest
check_PROGRAMS += hmactest
hmactest_SOURCES = hmactest.c

# ideatest
TESTS += ideatest
check_PROGRAMS += ideatest
ideatest_SOURCES = ideatest.c

# igetest
TESTS += igetest
check_PROGRAMS += igetest
igetest_SOURCES = igetest.c

# init_pledge.c

# key_schedule
TESTS += key_schedule
check_PROGRAMS += key_schedule
key_schedule_SOURCES = key_schedule.c

# keypairtest
TESTS += keypairtest.sh
keypairtest_CPPFLAGS = -I $(top_srcdir)/tls $(AM_CPPFLAGS)
check_PROGRAMS += keypairtest
keypairtest_SOURCES = keypairtest.c
EXTRA_DIST += keypairtest.sh

# lhash_test
TESTS += lhash_test
check_PROGRAMS += lhash_test
lhash_test_SOURCES = lhash_test.c

# md_test
TESTS += md_test
check_PROGRAMS += md_test
md_test_SOURCES = md_test.c $(TEST_HELPER_SRC)

noinst_HEADERS += mlkem_tests_util.h
noinst_HEADERS += parse_test_file.h

# mlkem_tests
TESTS += mlkem_tests.sh
check_PROGRAMS += mlkem_tests
mlkem_tests_SOURCES = mlkem_tests.c mlkem_tests_util.c parse_test_file.c
EXTRA_DIST += mlkem_tests.sh
EXTRA_DIST += mlkem768_decap_tests.txt
EXTRA_DIST += mlkem768_encap_tests.txt
EXTRA_DIST += mlkem768_keygen_tests.txt
EXTRA_DIST += mlkem768_nist_decap_tests.txt
EXTRA_DIST += mlkem768_nist_keygen_tests.txt
EXTRA_DIST += mlkem1024_decap_tests.txt
EXTRA_DIST += mlkem1024_encap_tests.txt
EXTRA_DIST += mlkem1024_keygen_tests.txt
EXTRA_DIST += mlkem1024_nist_decap_tests.txt
EXTRA_DIST += mlkem1024_nist_keygen_tests.txt

# mlkem_iteration_tests
TESTS += mlkem_iteration_tests
check_PROGRAMS += mlkem_iteration_tests
mlkem_iteration_tests_SOURCES = mlkem_iteration_tests.c mlkem_tests_util.c

# mlkem_unittest
TESTS += mlkem_unittest
check_PROGRAMS += mlkem_unittest
mlkem_unittest_SOURCES = mlkem_unittest.c mlkem_tests_util.c

# objectstest
TESTS += objectstest
check_PROGRAMS += objectstest
objectstest_SOURCES = objectstest.c

# ocsp_test
if ENABLE_EXTRATESTS
TESTS += ocsptest.sh
check_PROGRAMS += ocsp_test
ocsp_test_SOURCES = ocsp_test.c
endif
EXTRA_DIST += ocsptest.sh ocsptest.bat

# optionstest
TESTS += optionstest
check_PROGRAMS += optionstest
optionstest_SOURCES = optionstest.c

# pbkdf2
TESTS += pbkdf2
check_PROGRAMS += pbkdf2
pbkdf2_SOURCES = pbkdf2.c

# pidwraptest
# pidwraptest relies on an OS-specific way to give out pids and is generally
# awkward on systems with slow fork
if ENABLE_EXTRATESTS
TESTS += pidwraptest.sh
check_PROGRAMS += pidwraptest
pidwraptest_SOURCES = pidwraptest.c
endif
EXTRA_DIST += pidwraptest.sh

# pkcs7test
TESTS += pkcs7test
check_PROGRAMS += pkcs7test
pkcs7test_SOURCES = pkcs7test.c

# poly1305test
TESTS += poly1305test
check_PROGRAMS += poly1305test
poly1305test_SOURCES = poly1305test.c

# policy
TESTS += policy
check_PROGRAMS += policy
policy_CPPFLAGS = $(AM_CPPFLAGS) -DCERTSDIR=\"$(srcdir)\"
policy_SOURCES = policy.c
EXTRA_DIST += policy_intermediate.pem
EXTRA_DIST += policy_intermediate_any.pem
EXTRA_DIST += policy_intermediate_duplicate.pem
EXTRA_DIST += policy_intermediate_invalid.pem
EXTRA_DIST += policy_intermediate_mapped.pem
EXTRA_DIST += policy_intermediate_mapped_any.pem
EXTRA_DIST += policy_intermediate_mapped_oid3.pem
EXTRA_DIST += policy_intermediate_require.pem
EXTRA_DIST += policy_intermediate_require1.pem
EXTRA_DIST += policy_intermediate_require2.pem
EXTRA_DIST += policy_intermediate_require_duplicate.pem
EXTRA_DIST += policy_intermediate_require_no_policies.pem
EXTRA_DIST += policy_leaf.pem
EXTRA_DIST += policy_leaf_any.pem
EXTRA_DIST += policy_leaf_duplicate.pem
EXTRA_DIST += policy_leaf_invalid.pem
EXTRA_DIST += policy_leaf_none.pem
EXTRA_DIST += policy_leaf_oid1.pem
EXTRA_DIST += policy_leaf_oid2.pem
EXTRA_DIST += policy_leaf_oid3.pem
EXTRA_DIST += policy_leaf_oid4.pem
EXTRA_DIST += policy_leaf_oid5.pem
EXTRA_DIST += policy_leaf_require.pem
EXTRA_DIST += policy_leaf_require1.pem
EXTRA_DIST += policy_root.pem
EXTRA_DIST += policy_root2.pem
EXTRA_DIST += policy_root_cross_inhibit_mapping.pem

# pq_test
TESTS += pq_test
check_PROGRAMS += pq_test
pq_test_SOURCES = pq_test.c

# quictest
TESTS += quictest.sh
check_PROGRAMS += quictest
quictest_SOURCES = quictest.c
EXTRA_DIST += quictest.sh quictest.bat

# randtest
TESTS += randtest
check_PROGRAMS += randtest
randtest_SOURCES = randtest.c

# rc2_test
TESTS += rc2_test
check_PROGRAMS += rc2_test
rc2_test_SOURCES = rc2_test.c

# rc4_test
TESTS += rc4_test
check_PROGRAMS += rc4_test
rc4_test_SOURCES = rc4_test.c

# recordtest
TESTS += recordtest
check_PROGRAMS += recordtest
recordtest_SOURCES = recordtest.c

# record_layer_test
TESTS += record_layer_test
check_PROGRAMS += record_layer_test
record_layer_test_SOURCES = record_layer_test.c

# renegotiation_test
TESTS += renegotiation_test.sh
check_PROGRAMS += renegotiation_test
renegotiation_test_SOURCES = renegotiation_test.c
EXTRA_DIST += renegotiation_test.sh renegotiation_test.bat

# rfc3779
TESTS += rfc3779
rfc3779_CPPFLAGS = $(AM_CPPFLAGS)
check_PROGRAMS += rfc3779
rfc3779_SOURCES = rfc3779.c

# rfc5280time
check_PROGRAMS += rfc5280time
rfc5280time_SOURCES = rfc5280time.c
if SMALL_TIME_T
TESTS += rfc5280time_small.test
XFAIL_TESTS += rfc5280time_small.test
else
TESTS += rfc5280time
endif
EXTRA_DIST += rfc5280time_small.test

# rmd_test
TESTS += rmd_test
check_PROGRAMS += rmd_test
rmd_test_SOURCES = rmd_test.c

# rsa_method_test
TESTS += rsa_method_test
check_PROGRAMS += rsa_method_test
rsa_method_test_SOURCES = rsa_method_test.c

# rsa_padding_test
TESTS += rsa_padding_test
check_PROGRAMS += rsa_padding_test
rsa_padding_test_SOURCES = rsa_padding_test.c

# rsa_test
TESTS += rsa_test
check_PROGRAMS += rsa_test
rsa_test_SOURCES = rsa_test.c

# server.c

# servertest
TESTS += servertest.sh
check_PROGRAMS += servertest
servertest_SOURCES = servertest.c
EXTRA_DIST += servertest.sh servertest.bat

# sha_test
TESTS += sha_test
check_PROGRAMS += sha_test
sha_test_SOURCES = sha_test.c $(TEST_HELPER_SRC)

# shutdowntest
TESTS += shutdowntest.sh
check_PROGRAMS += shutdowntest
shutdowntest_SOURCES = shutdowntest.c
EXTRA_DIST += shutdowntest.sh shutdowntest.bat

# signertest
TESTS += signertest
check_PROGRAMS += signertest
signertest_CPPFLAGS = -I $(top_srcdir)/tls $(AM_CPPFLAGS) -DCERTSDIR=\"$(srcdir)\"
signertest_SOURCES = signertest.c
if !HAVE_PIPE2
signertest_SOURCES += compat/pipe2.c
endif

# sm2crypttest
# sm2evptest
# sm2sigtest

# sm3test
TESTS += sm3test
check_PROGRAMS += sm3test
sm3test_SOURCES = sm3test.c

# sm4test
TESTS += sm4test
check_PROGRAMS += sm4test
sm4test_SOURCES = sm4test.c

# ssl_get_shared_ciphers
TESTS += ssl_get_shared_ciphers
ssl_get_shared_ciphers_CPPFLAGS = $(AM_CPPFLAGS) -DCERTSDIR=\"$(srcdir)\"
check_PROGRAMS += ssl_get_shared_ciphers
ssl_get_shared_ciphers_SOURCES = ssl_get_shared_ciphers.c

# ssl_methods
TESTS += ssl_methods
check_PROGRAMS += ssl_methods
ssl_methods_SOURCES = ssl_methods.c

# ssl_set_alpn_protos
TESTS += ssl_set_alpn_protos
check_PROGRAMS += ssl_set_alpn_protos
ssl_set_alpn_protos_SOURCES = ssl_set_alpn_protos.c

# ssl_verify_param
TESTS += ssl_verify_param
check_PROGRAMS += ssl_verify_param
ssl_verify_param_SOURCES = ssl_verify_param.c

# ssl_versions
TESTS += ssl_versions
check_PROGRAMS += ssl_versions
ssl_versions_SOURCES = ssl_versions.c

# ssltest
TESTS += ssltest.sh
check_PROGRAMS += ssltest
ssltest_SOURCES = ssltest.c
EXTRA_DIST += ssltest.sh ssltest.bat
EXTRA_DIST += testssl testssl.bat
EXTRA_DIST += ca-int-ecdsa.crl ca-int-ecdsa.pem ca-int-rsa.crl ca-int-rsa.pem
EXTRA_DIST += ca-root-ecdsa.pem ca-root-rsa.pem
EXTRA_DIST += client1-ecdsa-chain.pem client1-ecdsa.pem client1-rsa-chain.pem
EXTRA_DIST += client1-rsa.pem client2-ecdsa-chain.pem client2-ecdsa.pem
EXTRA_DIST += client2-rsa-chain.pem client2-rsa.pem client3-ecdsa-chain.pem
EXTRA_DIST += client3-ecdsa.pem client3-rsa-chain.pem client3-rsa.pem
EXTRA_DIST += server1-ecdsa-chain.pem server1-ecdsa.pem
EXTRA_DIST += server1-rsa-chain.pem server1-rsa.pem server2-ecdsa-chain.pem
EXTRA_DIST += server2-ecdsa.pem server2-rsa-chain.pem server2-rsa.pem
EXTRA_DIST += server3-ecdsa-chain.pem server3-ecdsa.pem server3-rsa-chain.pem
EXTRA_DIST += server3-rsa.pem

# testdsa
TESTS += testdsa.sh
EXTRA_DIST += testdsa.sh testdsa.bat
EXTRA_DIST += openssl.cnf

# testenc
TESTS += testenc.sh
EXTRA_DIST += testenc.sh testenc.bat

# testrsa
TESTS += testrsa.sh
EXTRA_DIST += testrsa.sh testrsa.bat

# timingsafe
TESTS += timingsafe
check_PROGRAMS += timingsafe
timingsafe_SOURCES = timingsafe.c

# tlsexttest
TESTS += tlsexttest
check_PROGRAMS += tlsexttest
tlsexttest_SOURCES = tlsexttest.c

# tlslegacytest
TESTS += tlslegacytest
check_PROGRAMS += tlslegacytest
tlslegacytest_SOURCES = tlslegacytest.c

# tlstest
TESTS += tlstest.sh
check_PROGRAMS += tlstest
tlstest_SOURCES = tlstest.c
if !HAVE_PIPE2
tlstest_SOURCES += compat/pipe2.c
endif
EXTRA_DIST += tlstest.sh tlstest.bat

# tls_ext_alpn
TESTS += tls_ext_alpn
check_PROGRAMS += tls_ext_alpn
tls_ext_alpn_SOURCES = tls_ext_alpn.c

# tls_prf
TESTS += tls_prf
check_PROGRAMS += tls_prf
tls_prf_SOURCES = tls_prf.c

# utf8test
TESTS += utf8test
check_PROGRAMS += utf8test
utf8test_SOURCES = utf8test.c

# valid_handshakes_terminate
TESTS += valid_handshakes_terminate
check_PROGRAMS += valid_handshakes_terminate
valid_handshakes_terminate_SOURCES = valid_handshakes_terminate.c

# verifytest
TESTS += verifytest
check_PROGRAMS += verifytest
verifytest_SOURCES = verifytest.c

# x25519test
TESTS += x25519test
check_PROGRAMS += x25519test
x25519test_SOURCES = x25519test.c

# x509attribute
TESTS += x509attribute
check_PROGRAMS += x509attribute
x509attribute_SOURCES = x509attribute.c

# x509_algor
TESTS += x509_algor
check_PROGRAMS += x509_algor
x509_algor_SOURCES = x509_algor.c

# x509_asn1
TESTS += x509_asn1
check_PROGRAMS += x509_asn1
x509_asn1_SOURCES = x509_asn1.c

# x509_extensions_test
TESTS += x509_extensions_test
check_PROGRAMS += x509_extensions_test
x509_extensions_test_SOURCES = x509_extensions_test.c

# x509_info
TESTS += x509_info
check_PROGRAMS += x509_info
x509_info_SOURCES = x509_info.c

# x509_name_test
TESTS += x509_name_test
check_PROGRAMS += x509_name_test
x509_name_test_SOURCES = x509_name_test.c

# x509req_ext
TESTS += x509req_ext
check_PROGRAMS += x509req_ext
x509req_ext_SOURCES = x509req_ext.c
