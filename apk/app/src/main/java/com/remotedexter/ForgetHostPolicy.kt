package com.remotedexter

/**
 * How much of a pairing "Forget this host" is allowed to take with it.
 *
 * ## The distinction that did not exist before
 *
 * A pairing is made of three things: the host's identity and pin, which are per
 * host, and **this device's own Noise identity, which is one key shared by every
 * host it is paired with**. The host enrolls that key; it is what makes a
 * token-less reconnect work.
 *
 * With one host, forgetting the host and unpairing the device were the same
 * act, and [DeviceUnpair.forgetEverything] did both. With several they come
 * apart, and getting it wrong fails in one of two directions:
 *
 * - Drop the device identity while other hosts remain, and forgetting one host
 *   silently unpairs the phone from **all** of them. The other records survive,
 *   so the app still offers to reconnect — to hosts that will now refuse it.
 * - Keep the device identity when nothing remains, and a phone the user was
 *   told is unpaired is still enrolled at the last host, which would still let
 *   it in.
 *
 * So the rule is decided here, once, and tested, instead of being an `if` in a
 * click listener.
 */
object ForgetHostPolicy {

    /** What forgetting one host should actually remove. */
    enum class Scope {
        /**
         * Drop this host's record only. The device identity stays, because
         * other pairings are still using it.
         */
        ThisHostOnly,

        /**
         * Drop this host's record AND this device's identity. Chosen when
         * nothing is left that could still be using it — at which point
         * keeping it would leave a key the last host still recognises.
         */
        HostAndDeviceIdentity
    }

    /**
     * @param remainingAfterForget how many paired hosts are left once this one
     *   is gone.
     *
     * A negative count cannot happen and is treated as zero rather than as an
     * error: the conservative reading. Over-cleaning costs the user a QR scan;
     * under-cleaning leaves a key behind.
     */
    fun scopeFor(remainingAfterForget: Int): Scope =
        if (remainingAfterForget <= 0) Scope.HostAndDeviceIdentity else Scope.ThisHostOnly

    /**
     * Whether the user must be told the host may still recognise this phone.
     *
     * True whenever the device identity is being kept. **The app cannot revoke
     * itself at the host** — only the host's own Revoke does that — so a phone
     * that forgets one of several hosts is forgetting its own note, not
     * withdrawing permission. Saying "unpaired" there would be untrue, and the
     * remedy the user needs is at the other machine.
     */
    fun mustWarnHostStillKnowsUs(scope: Scope): Boolean = scope == Scope.ThisHostOnly
}
