package com.remotedexter.bootstrap18

import org.json.JSONObject

/**
 * Host-declared policy carried inside the invite.
 *
 * Property names are snake_case to mirror the JSON keys exactly. That is
 * deliberate: the invite is a wire format shared with the Rust host
 * (`modules/module17_bootstrap_invite`), and keeping one spelling for both ends
 * removes a whole class of rename bug — which is precisely the bug that broke
 * pairing on the March 2026 build (`lan_ip` vs `host_ip`).
 *
 * Note this policy is *advisory input from the host*, not a trust boundary. It
 * can only ever make the client stricter: every field either blocks the session
 * or does nothing. A forged invite cannot use it to loosen anything, because
 * signature verification and the host-key pin are enforced separately in
 * [SessionStarter] and are not policy-controlled.
 */
data class SecurityPolicy(
    val require_token: Boolean,
    val require_geo_fence: Boolean,
    val geo_fence_lat: Double?,
    val geo_fence_lon: Double?,
    val geo_fence_radius_m: Double?,
    val require_device_pairing: Boolean,
    val allowed_transports: List<String>
) {
    companion object {
        /** Transports assumed when the host does not name any. */
        private val DEFAULT_TRANSPORTS =
            listOf("wifi", "bluetooth", "usb", "lan", "wan")

        /**
         * Parse the nested `security_policy` object out of the *root* invite
         * object. Takes the root rather than the nested node so a missing
         * `security_policy` is a normal case rather than a caller-side null
         * check.
         *
         * Tolerant by construction: an absent object yields defaults, and every
         * read is optional or `has`-guarded. The geo-fence coordinates stay null
         * when absent rather than defaulting to 0.0 — (0, 0) is a real location
         * in the Atlantic, and defaulting there would silently place a fence
         * somewhere the user is not.
         */
        fun fromJson(obj: JSONObject): SecurityPolicy {
            val p = obj.optJSONObject("security_policy")
                ?: return SecurityPolicy(
                    require_token = true,
                    require_geo_fence = false,
                    geo_fence_lat = null,
                    geo_fence_lon = null,
                    geo_fence_radius_m = null,
                    require_device_pairing = false,
                    allowed_transports = DEFAULT_TRANSPORTS
                )

            val transports = mutableListOf<String>()
            p.optJSONArray("allowed_transports")?.let { arr ->
                for (i in 0 until arr.length()) transports.add(arr.getString(i))
            }

            return SecurityPolicy(
                require_token = p.optBoolean("require_token", true),
                require_geo_fence = p.optBoolean("require_geo_fence", false),
                geo_fence_lat = if (p.has("geo_fence_lat")) p.getDouble("geo_fence_lat") else null,
                geo_fence_lon = if (p.has("geo_fence_lon")) p.getDouble("geo_fence_lon") else null,
                geo_fence_radius_m =
                    if (p.has("geo_fence_radius_m")) p.getDouble("geo_fence_radius_m") else null,
                require_device_pairing = p.optBoolean("require_device_pairing", false),
                allowed_transports =
                    if (transports.isEmpty()) DEFAULT_TRANSPORTS else transports
            )
        }
    }
}
