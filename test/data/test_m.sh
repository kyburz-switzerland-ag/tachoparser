#!/usr/bin/env bash
for i in M_*.DDD ; do
  echo
  echo $i
  j=${i:16}
  k=$(../../cmd/dddsimple/dddsimple -input $i | jq -r .VuName | tail -c +6)
  if [[ "${j}" == "${k}" ]]; then
    echo OK
  else
    echo "NOT OK"
  fi
done