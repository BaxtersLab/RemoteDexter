package com.remotedexter

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * Nothing this app stores may leave the device by an extraction path.
 *
 * This guards a claim the code got wrong once. `RDService` stored the client's
 * X25519 private identity in `filesDir` and justified it with
 * `allowBackup=false`, which governs CLOUD BACKUP and not device-to-device
 * transfer. From API 31 a D2D transfer carries everything unless
 * `res/xml/data_extraction_rules.xml` excludes it, so a phone-to-phone move
 * would have cloned an enrolled identity onto a device the host never paired —
 * and it would have authenticated, because it holds the enrolled key.
 *
 * WHAT THIS TEST IS AND IS NOT. It reads the manifest and the rules file as
 * TEXT. It cannot prove the platform honours them; only a real D2D transfer
 * between two handsets can, and that is recorded as unverified rather than
 * implied. What it does prove is that the settings do not quietly disappear —
 * which is exactly how the gap arose, one of the two being absent while a
 * comment asserted the property they only hold together.
 */
class DataExtractionRulesTest {

    private val manifest = File("src/main/AndroidManifest.xml")
    private val rules = File("src/main/res/xml/data_extraction_rules.xml")

    /** Every domain Android can carry, so a new section cannot omit one. */
    private val allDomains = setOf(
        "root", "file", "database", "sharedpref", "external",
        "device_root", "device_file", "device_database", "device_sharedpref"
    )

    @Test
    fun the_manifest_disables_cloud_backup_and_points_at_the_extraction_rules() {
        assertTrue("manifest not found from ${File(".").absolutePath}", manifest.exists())
        val text = manifest.readText()
        assertTrue(
            "allowBackup=false covers API < 31 and must stay",
            text.contains("""android:allowBackup="false"""")
        )
        assertTrue(
            "without dataExtractionRules a D2D transfer carries everything on API 31+",
            text.contains("""android:dataExtractionRules="@xml/data_extraction_rules"""")
        )
    }

    @Test
    fun both_extraction_paths_exclude_every_domain_and_include_nothing() {
        assertTrue("rules file not found", rules.exists())
        val doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(rules)

        for (section in listOf("cloud-backup", "device-transfer")) {
            val nodes = doc.getElementsByTagName(section)
            assertEquals("exactly one <$section> section expected", 1, nodes.length)
            val el = nodes.item(0) as Element

            val excluded = el.getElementsByTagName("exclude").let { list ->
                (0 until list.length)
                    .map { (list.item(it) as Element).getAttribute("domain") }
                    .toSet()
            }
            assertEquals(
                "<$section> must exclude every domain; missing ${allDomains - excluded}",
                allDomains,
                excluded
            )

            // An <include> re-admits data and would silently defeat the
            // excludes around it, so the rule is that there are none at all.
            assertEquals(
                "<$section> must not include anything",
                0,
                el.getElementsByTagName("include").length
            )
        }
    }
}
