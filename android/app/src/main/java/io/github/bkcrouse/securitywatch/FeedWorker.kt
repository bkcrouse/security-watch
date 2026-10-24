package io.github.bkcrouse.securitywatch

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Polls data.json and notifies about entries that newly became "act now" or
 * newly matched the watchlist. The first run only records what's there, so
 * installing the app doesn't fire a burst of notifications.
 */
class FeedWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val items = Feed.fetch()
            val prefs = applicationContext.getSharedPreferences("feed", Context.MODE_PRIVATE)
            val seen: Set<String>? = prefs.getStringSet(KEY_SEEN, null)

            // One key per reason to alert, so an item that later gets added to
            // CISA KEV (fyi -> act) alerts again even if it was seen before.
            fun keys(i: Item) = buildList {
                if (i.isAct) add("act:${i.id}")
                if (i.watched) add("watch:${i.id}")
            }
            val current = items.flatMap { item -> keys(item).map { it to item } }
            val currentKeys = current.map { it.first }.toSet()

            if (seen != null) {
                val fresh = current.filter { it.first !in seen }.map { it.second }.distinctBy { it.id }
                    .sortedWith(compareByDescending<Item> { it.isAct }.thenByDescending { it.watched })
                Notifier.notifyNew(applicationContext, fresh)
            }
            // Remember only what's still in the feed, so the set doesn't grow forever.
            prefs.edit()
                .putStringSet(KEY_SEEN, currentKeys)
                .putLong(KEY_LAST_OK, System.currentTimeMillis())
                .apply()
            // Piggyback the (throttled) app update check on the feed check.
            runCatching { UpdateChecker.check(applicationContext) }
            Result.success()
        } catch (e: Exception) {
            Log.w(TAG, "feed check failed", e)
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        }
    }

    companion object {
        private const val TAG = "FeedWorker"
        private const val KEY_SEEN = "seen"
        private const val KEY_LAST_OK = "lastOk"
        private const val PERIODIC = "feed-periodic"
        private const val NOW = "feed-now"

        private val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        /** 15 minutes is the shortest interval Android allows for periodic work. */
        fun schedule(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<FeedWorker>(15, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(ctx)
                .enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun checkNow(ctx: Context) {
            val req = OneTimeWorkRequestBuilder<FeedWorker>().setConstraints(constraints).build()
            WorkManager.getInstance(ctx).enqueueUniqueWork(NOW, ExistingWorkPolicy.REPLACE, req)
        }
    }
}
