#!/bin/sh

. "$(dirname "$0")/vars"

mkdir -p "${SOFTHSM2_TOKENS}"

softhsm2-util --init-token --label "${TOKEN}" --free --so-pin "${SOPIN}" --pin "${PIN}"

