#!/bin/sh
# No remote access: clone only prepares a deterministic source directory.
for arg do last=$arg; done
case " $* " in
  *' clone '*) mkdir -p "$last/.git"; printf 'def example():\n    return 1\n' > "$last/example.py";;
  *' rev-parse '*) printf '0123456789abcdef0123456789abcdef01234567\n';;
  *' symbolic-ref '*) printf 'main\n';;
  *' config '*) exit 0;;
  *) exit 0;;
esac
