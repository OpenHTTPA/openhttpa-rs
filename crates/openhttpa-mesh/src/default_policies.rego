package openhttpa.mesh.lib

# Check if the TEE is trusted (production grade)
is_trusted_tee(claims) {
    claims.dbgstat == 0
}

# Verify hardware measurement against expected value
verify_measurement(actual, expected) {
    actual == expected
}

# Check if TCB is up to date
is_tcb_uptodate(status) {
    status == "UpToDate"
}

# Allow only agents with specific services
has_service(metadata, service) {
    metadata.services[_] == service
}

# Enforce PQC bindings
is_pqc_bound(input) {
    input.pqc_bound == true
}
