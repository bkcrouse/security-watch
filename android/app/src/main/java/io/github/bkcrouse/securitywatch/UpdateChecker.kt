package io.github.bkcrouse.securitywatch

import android.content.Context
import androidx.core.content.pm.PackageInfoCompat
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Sideloaded apps get no store updates, so the app asks GitHub Releases
 * whether a newer build exists. Releases are tagged android-v<build>, and
 * <build> is the versionCode CI stamps into the APK.
 */
object UpdateChecker {
    private const val API = "https://api.github.com/repos/bkcrouse/security-watch/releases/latest"
    const val APK_URL = "https://github.com/bkcrouse/security-watch/releases/latest/download/security-watch.apk"

    private const val PREFS = "updates"
    private const val KEY_LAST_CHECK = "lastCheck"
    private const val KEY_LATEST = "latestBuild"
    private const val KEY_NOTIFIED = "notifiedBuild"
    private const val INTERVAL_MS = 6 * 60 * 60 * 1000L   // GitHub allows 60 unauthenticated calls/hour

    fun installedBuild(ctx: Context): Long =
        PackageInfoCompat.getLongVersionCode(ctx.packageManager.getPackageInfo(ctx.packageName, 0))

    /** Newest build on GitHub, or null if the check failed. */
    private fun fetchLatest(): Long? {
        val conn = URL(API).openConnection() as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 15_000
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        return try {
            if (conn.responseCode != 200) return null
            val tag = JSONObject(conn.inputStream.bufferedReader().use { it.readText() }).optString("tag_name")
            Regex("""android-v(\d+)""").find(tag)?.groupValues?.get(1)?.toLongOrNull()
        } catch (_: Exception) {
            null
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Returns the newer build number if one is available. Hits the network at
     * most every 6 hours unless [force]; otherwise answers from the last check.
     * Posts the "update available" notification once per new build.
     */
    fun check(ctx: Context, force: Boolean = false): Long? {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        var latest = prefs.getLong(KEY_LATEST, 0)
        if (force || now - prefs.getLong(KEY_LAST_CHECK, 0) > INTERVAL_MS) {
            fetchLatest()?.let { latest = it }
            prefs.edit().putLong(KEY_LAST_CHECK, now).putLong(KEY_LATEST, latest).apply()
        }
        if (latest <= installedBuild(ctx)) return null
        if (prefs.getLong(KEY_NOTIFIED, 0) < latest) {
            Notifier.notifyUpdate(ctx, latest)
            prefs.edit().putLong(KEY_NOTIFIED, latest).apply()
        }
        return latest
    }
}
