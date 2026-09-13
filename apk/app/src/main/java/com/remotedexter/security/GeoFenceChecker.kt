package com.remotedexter.security

import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Great-circle distance test for the optional invite geo-fence.
 *
 * Only reached when the host sets `require_geo_fence`, which is off by default.
 */
object GeoFenceChecker {

    /** Mean Earth radius, metres (IUGG). */
    private const val EARTH_RADIUS_M = 6_371_008.8

    /**
     * True when the device is within [radiusMetres] of the fence centre.
     *
     * Uses the haversine formula rather than equirectangular approximation: the
     * cheap approximation degrades badly at high latitudes and across the
     * antimeridian, and a fence that silently grows near the poles is a security
     * control that stops controlling anything.
     *
     * A non-positive radius admits nothing. Treating it as "no constraint" would
     * turn a misconfigured fence into a disabled one.
     */
    fun isWithinFence(
        deviceLat: Double,
        deviceLon: Double,
        fenceLat: Double,
        fenceLon: Double,
        radiusMetres: Double
    ): Boolean {
        if (radiusMetres <= 0.0) return false
        return distanceMetres(deviceLat, deviceLon, fenceLat, fenceLon) <= radiusMetres
    }

    /** Great-circle distance between two WGS84 points, in metres. */
    fun distanceMetres(
        lat1: Double,
        lon1: Double,
        lat2: Double,
        lon2: Double
    ): Double {
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val rLat1 = Math.toRadians(lat1)
        val rLat2 = Math.toRadians(lat2)

        val a = sin(dLat / 2).let { it * it } +
            cos(rLat1) * cos(rLat2) * sin(dLon / 2).let { it * it }

        // Clamp before asin: accumulated float error can push `a` a hair above 1
        // for near-antipodal points, and asin(>1) is NaN.
        return 2 * EARTH_RADIUS_M * asin(min(1.0, sqrt(a)))
    }
}
