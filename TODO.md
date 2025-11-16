# TODO

## 2025-11-16

- feature to create a ``SString`` with a callback function to handle
  non-utf8 bytes so that it becomes trivial to write a program what
  replaces all non-utf8 bytes with their hexadecimal representation
  syntax-highlighted. this program can then be used to debug the
  output of ``man gawk`` so that one easily see why the output of
  ``man gawk | ansistrip | bat`` displays weird duplicated chars
