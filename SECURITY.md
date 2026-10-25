# Security

Version 0.1.x is supported. Report vulnerabilities through
[private vulnerability reporting](https://github.com/KanadeK/hostgrant-diff/security/advisories/new).
Use synthetic input. Do not publish private input or credentials in an issue.

The program does not access the network, execute input, or change input files.
It reads the files explicitly supplied on the command line. Parsing is bounded;
the documented model does not cover every possible disclosure or access path.
Review README limitations before interpreting a result. Reports may themselves
describe sensitive system structure. Runtime dependencies: Python standard library only.
