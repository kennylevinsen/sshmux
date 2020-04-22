# sshmux [![GoDoc](https://godoc.org/github.com/kennylevinsen/sshmux?status.svg)](http://godoc.org/github.com/kennylevinsen/sshmux) [![Build Status](https://travis-ci.org/kennylevinsen/sshmux.svg?branch=master)](https://travis-ci.org/kennylevinsen/sshmux) [![Go Report Card](https://goreportcard.com/badge/kennylevinsen/sshmux)](https://goreportcard.com/report/kennylevinsen/sshmux)

SSH multiplexing library, allowing you to write "jump host" style proxies.

Supports both transparent `-oProxyJump=sshmux-server` style jumps, as well as interactive session forwarding (with some limitations).

# But i just want to run it...

Look at sshmuxd instead, then: https://github.com/kennylevinsen/sshmuxd. For fleet management, look at https://github.com/kennylevinsen/sshfleet.