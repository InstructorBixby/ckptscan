# ckptscan

Scans model checkpoints for code that runs when you load them.

A pickle is not a data format. It is a little stack program, and
`torch.load` is its interpreter. `GLOBAL` imports whatever module and
attribute the file names; `REDUCE` calls it with arguments the file
supplies. That is arbitrary code execution as the *documented
behaviour* of the format, and the whole ecosystem distributes weights
this way.

**This tool never unpickles anything.** It walks the opcode stream with
`pickletools.genops`, which parses without executing, and reports what
the stream *would* do. A scanner that has to run the file to decide
whether running the file is safe is not a scanner.

    python scan.py model.pkl
