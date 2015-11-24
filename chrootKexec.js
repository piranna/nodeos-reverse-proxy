#! /usr/bin/env node

var kexec = require('kexec')
var posix = require('posix')


var uid = parseInt(process.argv[2])
var gid = parseInt(process.argv[3])


posix.chroot('.')

posix.setregid(gid, gid)
posix.setreuid(uid, uid)

kexec(process.argv[4], process.argv.slice(5))
