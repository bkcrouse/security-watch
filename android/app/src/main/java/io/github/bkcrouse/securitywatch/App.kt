package io.github.bkcrouse.securitywatch

import android.app.Application

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifier.createChannels(this)
        FeedWorker.schedule(this)
    }
}
