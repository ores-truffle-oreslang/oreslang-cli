# Mandatory nonblocking guest I/O

CLI run and compiler-client checks (including LSP checks) always assert
`--core-io=native-async-only`. Permission flags and configured executable/prefix
arguments cannot downgrade it; duplicate/off/legacy policies are rejected by the
compiler. There is no retry without the assertion. Older incompatible tools
fail closed. The assertion is redundant with a current compiler's unconditional
default, and also prevents accidentally selecting a permissive older toolchain.
The separately installed test CLI retains its own versioned execution contract;
its subprocess success alone is not proof of native asynchronous guest I/O.
