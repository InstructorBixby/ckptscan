"""One module per thing that can be analysed.

An analyser takes bytes (or a path) plus a context and returns
findings. It does not print, does not decide exit codes, and does not
know what SARIF is.
"""
