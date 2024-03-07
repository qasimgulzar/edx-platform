#!/bin/bash

DD_TRACE_PYMONGO_ENABLED=false ddtrace-run "$@"
