#!/bin/sh

PIN=user
#SOPIN=sopin
TOKEN=test1
OBJECT=key
ID=0
KEY_SIZE=2048
TEMPLATE=my.template

for PROVIDER in /usr/lib64/pkcs11/libsofthsm2.so /usr/lib64/softhsm/libsofthsm2.so; do
	[ -f "${PROVIDER}" ] && break
done
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

export GNUTLS_PIN="${PIN}"

for i in 1 2 3; do
	myobject="${OBJECT}${i}"
	myid="${ID}${i}"
	mytemplate="${MYTMP}/${i}.template"

	cat > "${mytemplate}" << __EOF__
cn = "Dummy ${myid}"
serial = 00${myid}
expiration_days = 3600
__EOF__

	p11tool \
		--provider="${PROVIDER}" \
		--login \
		--generate-rsa \
		--bits="${KEY_SIZE}" \
		--id="${myid}" --label="${myobject}" \
		"pkcs11:token=${TOKEN}" \
		|| die "Cannot generate key"
	certtool \
		--provider="${PROVIDER}" \
		--generate-self-signed \
		--load-privkey="pkcs11:token=${TOKEN};object=${myobject};type=private" \
		--load-pubkey="pkcs11:token=${TOKEN};object=${myobject};type=public" \
		--template="${mytemplate}" \
		--outfile="${MYTMP}/cert.pem" \
		|| die "Cannot enroll certificate"
	p11tool \
		--provider="${PROVIDER}" \
		--login \
		--write \
		--id="${myid}" --label="${myobject}" \
		--no-mark-private \
		--load-certificate="${MYTMP}/cert.pem" \
		"pkcs11:token=${TOKEN}" \
		|| die "Cannot store certificate"
done
