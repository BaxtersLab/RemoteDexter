package com.remotedexter

/**
 * What this variant compiles in. **Debug copy — see the release one beside it.**
 *
 * There are exactly two files with this name, one per build type, and they
 * differ in one constant. That is the point: the release variant does not
 * compile a true value that some runtime check has to be trusted to catch, it
 * compiles `false`, and Kotlin inlines it at every use site. The affordance is
 * dead code in a release build rather than disabled code.
 *
 * `BuildConfig.DEBUG` would have said the same thing in one file. Two files were
 * chosen because this one is readable without knowing what AGP generates, the
 * difference between the variants is a diff rather than a flag lookup, and the
 * claim "the release build cannot do this" is then a claim about which source
 * file was compiled — which the gate can check, and which no misconfiguration
 * of `buildFeatures` can quietly change.
 *
 * Both copies are asserted by an executed test, one per unit-test variant:
 * `testDebug/BuildProfileDebugTest` and `testRelease/BuildProfileReleaseTest`.
 * A shared test cannot make this claim, because it only ever sees one of them.
 */
internal object BuildProfile {

    /**
     * Whether [HeldKeyPolicy] may authorise a lone key `Down`.
     *
     * True here, false in the release copy. See [HeldKeyLatch] for why the
     * affordance exists and what Windows round 13 could not otherwise prove.
     */
    const val HELD_KEY_AFFORDANCE = true

    /** Names the variant in logs, so a report cannot silently be from the wrong build. */
    const val NAME = "debug"
}
