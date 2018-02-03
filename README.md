# hactool

![License](https://img.shields.io/badge/license-ISC-blue.svg)

hactool is a tool to view information about, decrypt, and extract common file formats for the Nintendo Switch, especially Nintendo Content Archives.

It is heavily inspired by [ctrtool](https://github.com/profi200/Project_CTR/tree/master/ctrtool).

## Usage

```
Usage: hactool [options...] <file>
Options:
-i, --info        Show file info.
                      This is the default action.
-x, --extract     Extract data from file.
                      This is also the default action.
  -r, --raw          Keep raw data, don't unpack.
  -y, --verify       Verify hashes and signatures.
  -d, --dev          Decrypt with development keys instead of retail.
  -t, --intype=type  Specify input file type [nca, pfs0]
  --titlekey=key     Set title key for Rights ID crypto titles.
  --contentkey=key   Set raw key for NCA body decryption.
NCA options:
  --section0=file    Specify Section 0 file path.
  --section1=file    Specify Section 1 file path.
  --section2=file    Specify Section 2 file path.
  --section3=file    Specify Section 3 file path.
  --section0dir=dir  Specify Section 0 directory path.
  --section1dir=dir  Specify Section 1 directory path.
  --section2dir=dir  Specify Section 2 directory path.
  --section3dir=dir  Specify Section 3 directory path.
  --exefs=file       Specify ExeFS file path. Overrides appropriate section file path.
  --exefsdir=dir     Specify ExeFS directory path. Overrides appropriate section directory path.
  --romfs=file       Specify RomFS file path. Overrides appropriate section file path.
  --romfsdir=dir     Specify RomFS directory path. Overrides appropriate section directory path.
  --listromfs        List files in RomFS.
  --baseromfs        Set Base RomFS to use with update partitions.
  --basenca        Set Base NCA to use with update partitions.
PFS0 options:
  --outdir=dir       Specify PFS0 directory path.```

## Building

Copy `config.mk.template` to `config.mk`, make changes as required, and then run `make`.
If your `make` is not GNU make (e.g. on BSD variants), you need to call `gmake` instead.

You may need [libiconv](https://www.gnu.org/software/libiconv/) when not building on Linux.
If on Windows, I recommend using MinGW.

## Licensing

This software is licensed under the terms of the ISC License.  
You can find a copy of the license in the LICENSE file.
