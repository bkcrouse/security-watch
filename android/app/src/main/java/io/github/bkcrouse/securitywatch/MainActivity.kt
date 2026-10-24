package io.github.bkcrouse.securitywatch

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.ViewGroup
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import org.json.JSONObject

/** Hosts the live dashboard; links that leave the site open in the browser. */
class MainActivity : Activity() {

    private lateinit var web: WebView
    private val siteUri: Uri = Uri.parse(SITE_URL)

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WindowCompat.setDecorFitsSystemWindows(window, false)
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }

        val root = FrameLayout(this).apply { setBackgroundColor(BG) }
        web = WebView(this).apply {
            setBackgroundColor(BG)
            settings.javaScriptEnabled = true      // the dashboard is a JS app
            settings.domStorageEnabled = true      // remembers theme and filters
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.setSupportMultipleWindows(false)
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    val u = request.url
                    if (isSite(u)) return false
                    openExternally(u)
                    return true
                }
            }
        }
        root.addView(web, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        setContentView(root)

        // Edge-to-edge (forced on Android 15): keep content clear of the system bars.
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }

        if (savedInstanceState != null) web.restoreState(savedInstanceState)
        else web.loadUrl(urlFor(intent))

        askForNotifications()
        FeedWorker.checkNow(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val id = intent.getStringExtra(EXTRA_ID) ?: return
        // Page already loaded: ask it to open the row; otherwise load it with the hash.
        web.evaluateJavascript("(window.swOpen ? (swOpen(${JSONObject.quote(id)}), true) : false)") { result ->
            if (result != "true") web.loadUrl(urlFor(intent))
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web.saveState(outState)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else @Suppress("DEPRECATION") super.onBackPressed()
    }

    override fun onDestroy() {
        web.destroy()
        super.onDestroy()
    }

    private fun urlFor(intent: Intent?): String {
        val id = intent?.getStringExtra(EXTRA_ID)
        // The dashboard opens and scrolls to a row when the URL hash is its ID.
        return if (id.isNullOrBlank()) SITE_URL else SITE_URL + "#" + Uri.encode(id)
    }

    private fun isSite(u: Uri): Boolean =
        u.scheme == "https" && u.host == siteUri.host && (u.path ?: "").startsWith(siteUri.path ?: "/")

    private fun openExternally(u: Uri) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, u))
        } catch (_: ActivityNotFoundException) {
        }
    }

    private fun askForNotifications() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    companion object {
        const val EXTRA_ID = "id"
        private val BG = Color.parseColor("#121315")
    }
}
