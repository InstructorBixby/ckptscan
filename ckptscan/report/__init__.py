"""Rendering findings. One module per output format.

Every renderer takes the same list of findings and the same context,
and none of them decides anything: severities are already resolved and
suppressions already applied before a renderer sees the list.
"""
