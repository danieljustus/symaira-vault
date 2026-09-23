import SymvaultRustCore

let identity = symvault_generate_identity()
precondition(identity.error.len == 0 && identity.output.len > 0)
symvault_buffer_free(identity.output)
symvault_buffer_free(identity.error)
