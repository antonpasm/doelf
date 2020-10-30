# doelf

The plugin produce ELF file with the symbols recognized by IDA Pro. This allows us to use the power of IDA in recognizing functions (analysis, FLIRT signatures, manual creation, renaming, etc), but not be limited to the exclusive use of this tools.

Based on a [syms2elf](https://github.com/danigargu/syms2elf)


## Installation

Just copy `doelf.py` to your IDA's plugins folder.


## Differences from [syms2elf](https://github.com/danigargu/syms2elf)

Doesn't require source elf file. You can create an ELF with debug information from any dump file (e.g. dump of controller firmware)


## Authors

  * PASm
