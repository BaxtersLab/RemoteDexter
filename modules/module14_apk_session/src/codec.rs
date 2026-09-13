pub fn encode_negotiation_request(req: &crate::commands::NegotiationRequest) -> Vec<u8> {
    req.client_version.to_le_bytes().to_vec()
}

pub fn decode_negotiation_response(bytes: &[u8]) -> Option<crate::events::NegotiationResponse> {
    if bytes.len() == 4 {
        let server_version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Some(crate::events::NegotiationResponse { server_version })
    } else {
        None
    }
}