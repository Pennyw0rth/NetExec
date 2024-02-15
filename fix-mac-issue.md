# Quick explanation about the issue.

The other day trying to install `NetExec` on MacOS ARM arch ( M2 Pro ) I got the following error:

```bash
$ pipx install git+https://github.com/PennywOrth/NetExec --force
  Fatal error from pip prevented installation. Full pip output in file:
    /Users/0xh311x/.local/pipx/logs/cmd_2024-02-15_01.41.45._pip_errors.log
  pip failed to build package:
    aardwolf
  Some possibly relevant errors from pip install:
    error: subprocess-exited-with-error error: can't find Rust compiler
    Error installing netexec from
  spec 'gitthttps://github.com/PennywOrth/NetExeC'
```

# Quick fix

You need to install / re-install your `rust` compiler using `homebrew`
```bash
brew install rust
```
