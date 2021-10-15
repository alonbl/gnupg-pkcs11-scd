#!/bin/sh

. "$(dirname "$0")/vars"

SUBJECT="/CN=Test"

for P11ENGINE in /usr/lib64/engines-1.1/pkcs11.so /usr/lib64/engines/pkcs11.so; do
	[ -f "${P11ENGINE}" ] && break
done

die() {
	local m="$1"
	echo "FATAL: ${m}" >&2
	exit 1
}

MYTMP=
trap cleanup 0
cleanup() {
	[ -n "${MYTMP}" ] && rm -fr "${MYTMP}"
}
MYTMP="$(mktemp -d)"

#softhsm2-util --init-token --label "${TOKEN}" --free --so-pin "${SOPIN}" --pin "${PIN}"

for i in 1 2 3; do
	myobject="${OBJECT}${i}"
	myid="${ID}${i}"
	mysubject="${SUBJECT} ${i}"

	pkcs11-tool \
		--module "${PROVIDER}" \
		--token-label "${TOKEN}" \
		--login \
		--pin "${PIN}" \
		--id "${myid}" --label "${myobject}" \
		--key-type rsa:${KEY_SIZE} \
		--always-auth \
		--keypairgen || \
		die "Cannot generate key"

# twice req as it succeeds at second....
	openssl << __EOF__ || die "Cannot enroll certificate"

engine -t dynamic \
	-pre SO_PATH:${P11ENGINE} \
	-pre ID:pkcs11 \
	-pre LIST_ADD:1 \
	-pre LOAD \
	-post MODULE_PATH:${PROVIDER}

req \
	-engine pkcs11 \
	-new \
	-key "pkcs11:token=${TOKEN};id=%0$i;type=private;pin-value=${PIN}" \
	-keyform engine -out "${MYTMP}/req.pem" -text -x509 -subj "${mysubject}"
req \
	-engine pkcs11 \
	-new \
	-key "pkcs11:token=${TOKEN};id=%0$i;type=private;pin-value=${PIN}" \
	-keyform engine -out "${MYTMP}/req.pem" -text -x509 -subj "${mysubject}"

x509 \
	-engine pkcs11 \
	-signkey "pkcs11:token=${TOKEN};id=%0$i;type=private;pin-value=${PIN}" \
	-keyform engine -in "${MYTMP}/req.pem" -out "${MYTMP}/cert.der" -outform DER

__EOF__

	pkcs11-tool \
		--module "${PROVIDER}" \
		--token-label "${TOKEN}" \
		--login \
		--pin "${PIN}" \
		--id "${myid}" --label "${myobject}" \
		--type cert \
		--write-object \
		"${MYTMP}/cert.der" || \
		die "Cannot store certificate"
done
