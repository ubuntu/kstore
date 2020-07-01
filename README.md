# kstore
Unlocks a LUKS encrypted key store that contains key of user's encrypted file
system.

## About

This software is made of 2 components: a PAM module and a helper shell script.

### PAM module

The PAM module is used for user authentication, session start and end.

During user authentication, it calls the helper script user\_kstore to unlock
the user's key store containing the keys that will decrypt its partition or
file system.

The password is read from stdin.

When the session starts, it locks the home directory to prevent systemd from
auto-unmounting it. The lock is released when the session ends.

When there is no active session left and the lock file is removed, systemd
autofs will unmount the home directory.

### user\_kstore

This helper script used to lock and unlock a LUKS encrypted user key store.

#### Synopsis

This helper script used to lock and unlock a LUKS encrypted user key store.

```
Usage: user_kstore [COMMAND] [OPTIONS...]
```

#### Commands

```
unlock  Open the keystore, need passphrase on stdin.
lock    Close the keystore
```

#### Options

```
-h, --help      This help
-d, --debug     Enable debug mode
```
