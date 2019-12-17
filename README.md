# r2db

WIP Project format for radare2.
**This is not meant to actually be used yet! All documentation is for developers.**

## Project Format

A project is one namespaced (nested) SDB.
Each component gets its own namespace and can nest it further.
The high-level progress of this implementation is tracked in #3.
Serializations for different components and data objects are defined by a pair of load/save functions in [r_serialize.h](include/r_serialize.h).

These serializations MUST correctly handle all edge cases that may occur in the data, such as special characters or '\0' characters.
To do this, json can be used in values, which will take care of all necessary escaping.
Printing json is done with pj, parsing with nxjson. For binary data, base64 should be used.
`sdb_array_*` must not be used because it can be easily corrupted.

## Version

The project format has a version number associated with it.
Each time the format changes, it is incremented, so when loading a project with an older versions, migrations will be performed.
More discussion about this is happening in #1.

## Tests

Every possible field in every structure must be covered by at least one unit test in [test/unit](test/unit).
r2r command tests can be written as well in [test/db](test/db).

## Building

r2db is currently developed as a standalone RCore plugin, but planned to be merged into the radare2 codebase when finalized.
Make sure that you have cloned the nxjson submodule before building.
Then building and installing works like this:

```
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=~/.local ..
make
make install
```

## Usage

```
[0x00000000]> PN?
Usage: PN   # Projects
| PNs[file]  save project
| PNl[file]  load project
```

