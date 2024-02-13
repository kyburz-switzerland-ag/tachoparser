#!/usr/bin/env bash
for i in C_*.DDD ; do
  echo
  echo $i
  j=${i:16}
  k=$(../../cmd/dddsimple/dddsimple -card -input $i | jq -r .CardName | tail -c +6)
  if [[ "${j}" == "${k}" ]]; then
    echo OK
  else
    echo "NOT OK"
  fi
done