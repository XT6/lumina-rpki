# LUMINA RPKI VALIDATOR

## what

We will write an rpki relying party tool from scratch, using only the RFC documents in txt format and some test cases we will create with Barry (insert barry URL here).

## tooling

Target is Elixir running on the Erlang VM. We may need accesories like ASN.1 extraction tools from the RFCs themselves. 

## high level features

- TAL parsing
- Repository retrieval over rsync initially, RRDP later
- Repository validation (cryptographic)
- REpository validation (resource inclusion)
- TXT VRP output
- JSON VRP + ASPA output

## how

We work on github. We open milestones for large work packages. We open issues filed against milestones. Issues should be atomic enough that they can be reasonably tested. 

We create unit tests for anything that can be unit tested. 

Each issue has tests it has to pass. No issue can be closed without tests passing unless explicitly acknowledged by me.

No milestone can be closed without all tests passing as well. 