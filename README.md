# Unpyprotect
An unpacker for [Angelic47](https://github.com/Angelic47)'s Python 2.7 bytecode protector, [PyProtect](https://pyprotect.angelic47.com/).

I wrote this as part of a (unreleased) blog post regarding how to use `xdis` and `xasm` to deal with obfsucated bytecode across python versions.

# Usage
`py -3 -m pip install -r requirements.txt`

`py -3 unpyprotect.py [--decode-utf8] <your_pyprotected_file.pyc>`
