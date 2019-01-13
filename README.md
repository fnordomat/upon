# Upon

This is work in progress.

Start one process when another (specified by PID) quits, or perform an action when a process whose commandline begins with a given prefix starts. The action can be: trigger another command or send the new process a SIGSTOP as soon as it is detected.

## Prequisites

Linux with CONFIG_CONNECTOR=y CONFIG_PROC_EVENTS=y configured.

## Usage

```
upon exec m"xyz" "run abc"
upon exit p4711 "run abc"
upon -vv exec m"/usr/lib/firefox/firefox" sigstop
```

## See also

[SO Q 6075013](https://stackoverflow.com/questions/6075013/how-to-detect-the-launching-of-programs-on-linux_

* The pwait(1) command
[https://github.com/chneukirchen/extrace/](https://github.com/chneukirchen/extrace/)
* The waitforpid command
[https://github.com/stormc/waitforpid](https://github.com/stormc/waitforpid)

## Acknowledgments

Thanks to the various people who shared their "cn_proc" C code under FLOSS licenses.

## TODO

Make sure it is as safe as it can be. Identify and implement missing features (regex matching; command line arguments for the "run" action). More testing. Improve the code. Optimize.

