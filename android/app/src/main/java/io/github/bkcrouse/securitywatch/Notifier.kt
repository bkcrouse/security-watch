package io.github.bkcrouse.securitywatch

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object Notifier {
    private const val CH_ACT = "act"
    private const val CH_WATCH = "watch"
    private const val GROUP = "security-watch"
    private const val SUMMARY_ID = 1
    private const val MAX_INDIVIDUAL = 6
    private const val ACCENT = 0xFFD6452F.toInt()

    /** Two channels, so either can be muted from Android's notification settings. */
    fun createChannels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CH_ACT, "Act now", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Vulnerabilities exploited in the wild and malicious packages"
            }
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_WATCH, "Watchlist", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "New entries that match your watchlist"
            }
        )
    }

    private fun allowed(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < 33 ||
            ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    private fun openIntent(ctx: Context, id: String?): PendingIntent {
        val intent = Intent(ctx, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (id != null) intent.putExtra(MainActivity.EXTRA_ID, id)
        return PendingIntent.getActivity(
            ctx, id?.hashCode() ?: 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    fun notifyNew(ctx: Context, items: List<Item>) {
        if (items.isEmpty() || !allowed(ctx)) return
        val nm = NotificationManagerCompat.from(ctx)

        try {
            for (item in items.take(MAX_INDIVIDUAL)) {
                val prefix = when {
                    item.kind == "malware" -> "Malicious package"
                    item.isAct -> "Act now"
                    else -> "Watchlist"
                }
                val reasons = item.why.joinToString(" · ")
                val body = listOf(reasons, item.note).filter { it.isNotBlank() }.joinToString("\n\n")
                val n = NotificationCompat.Builder(ctx, if (item.isAct) CH_ACT else CH_WATCH)
                    .setSmallIcon(R.drawable.ic_notify)
                    .setColor(ACCENT)
                    .setContentTitle("$prefix: ${item.label}")
                    .setContentText(item.shortTitle)
                    .setStyle(NotificationCompat.BigTextStyle().bigText("${item.shortTitle}\n\n$body".trim()))
                    .setSubText(item.id)
                    .setContentIntent(openIntent(ctx, item.id))
                    .setAutoCancel(true)
                    .setGroup(GROUP)
                    .setPriority(if (item.isAct) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
                    .build()
                nm.notify(item.id.hashCode(), n)
            }

            if (items.size > 1) {
                val inbox = NotificationCompat.InboxStyle()
                items.take(7).forEach { inbox.addLine("${it.label}: ${it.shortTitle}") }
                if (items.size > 7) inbox.setSummaryText("+${items.size - 7} more")
                val acts = items.count { it.isAct }
                val summary = NotificationCompat.Builder(ctx, if (acts > 0) CH_ACT else CH_WATCH)
                    .setSmallIcon(R.drawable.ic_notify)
                    .setColor(ACCENT)
                    .setContentTitle("${items.size} new in Security Watch")
                    .setContentText(if (acts > 0) "$acts to act on now" else "Watchlist matches")
                    .setStyle(inbox)
                    .setGroup(GROUP)
                    .setGroupSummary(true)
                    .setContentIntent(openIntent(ctx, null))
                    .setAutoCancel(true)
                    .build()
                nm.notify(SUMMARY_ID, summary)
            }
        } catch (_: SecurityException) {
            // Permission revoked between the check and the post; nothing to do.
        }
    }
}
