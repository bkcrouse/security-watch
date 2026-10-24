plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// CI passes these; local builds fall back to debug signing and versionCode 1.
val keystorePath: String? = System.getenv("SW_KEYSTORE")
val keystorePassword: String? = System.getenv("SW_KEYSTORE_PASSWORD")
val buildNumber: Int = (System.getenv("SW_VERSION_CODE") ?: "1").toInt()

android {
    namespace = "io.github.bkcrouse.securitywatch"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.bkcrouse.securitywatch"
        minSdk = 26
        targetSdk = 35
        versionCode = buildNumber
        versionName = "1.0.$buildNumber"
    }

    signingConfigs {
        create("release") {
            if (keystorePath != null) {
                storeFile = file(keystorePath)
                storePassword = keystorePassword
                keyAlias = "securitywatch"
                keyPassword = keystorePassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (keystorePath != null) signingConfigs.getByName("release")
                            else signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
}
