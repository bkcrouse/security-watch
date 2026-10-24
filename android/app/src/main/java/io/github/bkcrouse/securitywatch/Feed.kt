package io.github.bkcrouse.securitywatch

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

const val SITE_URL = "https://bkcrouse.github.io/security-watch/"
private const val DATA_URL = SITE_URL + "data.json"

data class Item(
    val id: String,
    val title: String,
    val vendor: String,
    val product: String,
    val tier: String,
    val watched: Boolean,
    val kind: String,
    val why: List<String>,
    val note: String,
) {
    val isAct get() = tier == "act"

    /** "Fortinet FortiOS", "PHP" (not "PHP PHP"), or the CVE id as a last resort. */
    val label: String
        get() {
            val v = vendor.trim()
            val p = product.trim()
            return when {
                v.isEmpty() && p.isEmpty() -> id
                p.isEmpty() || p.equals(v, true) || p.startsWith("$v ", true) -> p.ifEmpty { v }
                else -> "$v $p"
            }
        }

    /** Title with the product prefix stripped, so headlines don't repeat it. */
    val shortTitle: String
        get() {
            val t = title.ifBlank { id }
            return if (t.startsWith(label, true)) t.substring(label.length).trimStart(' ', ':', '-', '—', '–').ifBlank { t } else t
        }
}

object Feed {
    /** Downloads data.json; the timestamp defeats the Pages CDN cache. */
    fun fetch(): List<Item> {
        val conn = URL("$DATA_URL?t=${System.currentTimeMillis() / 60_000}").openConnection() as HttpURLConnection
        conn.connectTimeout = 20_000
        conn.readTimeout = 30_000
        conn.setRequestProperty("Accept", "application/json")
        conn.setRequestProperty("Cache-Control", "no-cache")
        try {
            if (conn.responseCode !in 200..299) error("HTTP ${conn.responseCode}")
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            return parse(body)
        } finally {
            conn.disconnect()
        }
    }

    fun parse(body: String): List<Item> {
        val items: JSONArray = JSONObject(body).optJSONArray("items") ?: return emptyList()
        return (0 until items.length()).mapNotNull { i ->
            val o = items.optJSONObject(i) ?: return@mapNotNull null
            val why = o.optJSONArray("why")
            Item(
                id = o.optString("id"),
                title = o.optString("title"),
                vendor = o.optString("vendor"),
                product = o.optString("product"),
                tier = o.optString("tier"),
                watched = o.optBoolean("watched"),
                kind = o.optString("kind"),
                why = if (why == null) emptyList() else (0 until why.length()).map { why.optString(it) },
                note = o.optString("note"),
            )
        }.filter { it.id.isNotBlank() }
    }
}
