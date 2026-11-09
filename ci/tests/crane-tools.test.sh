#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu

crane version
crane auth login --help > /dev/null
crane index append --help > /dev/null
crane copy --help > /dev/null
crane manifest --help > /dev/null
echo "PASS: manifest and release jobs have a usable crane"
