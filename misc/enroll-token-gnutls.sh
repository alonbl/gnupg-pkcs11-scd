#!/bin/sh

. "$(dirname "$0")/vars"

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

[ "${ALWAYS_AUTH}" -eq 0 ] || die "Always auth is not supported by gnutls"

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
