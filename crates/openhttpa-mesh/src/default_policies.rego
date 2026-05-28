package openhttpa.mesh.lib

# Check if the TEE is trusted (production grade)
is_trusted_tee(claims) if {
    claims.dbgstat == 0
}

# Verify hardware measurement against expected value
verify_measurement(actual, expected) if {
    actual == expected
}

# Check if TCB is up to date
is_tcb_uptodate(status) if {
    status == "UpToDate"
}

# Allow only agents with specific services
has_service(metadata, service) if {
    metadata.services[_] == service
}

# Enforce PQC bindings
is_pqc_bound(input) if {
    input.pqc_bound == true
}

