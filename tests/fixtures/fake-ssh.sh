#!/bin/sh
set -eu

for argument do
    printf '%s\0' "$argument"
done
