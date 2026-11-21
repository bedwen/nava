package com.nava.app.di

import android.app.Application
import android.content.Context
import com.nava.app.locale.AndroidResourceMessageTemplateProvider
import com.nava.app.locale.MessageTemplateProvider

/**
 * Android [Application] entry point owning the single process-wide [AppContainer] composition root.
 *
 * Cold Start `< 400 ms` Invariant (PLAN.md Section 2.3 & Requirement 10):
 * - [onCreate] constructs [AppContainer] with `lazy` dependencies and binds lightweight platform
 *   service hooks ([AppContainer.bindPlatformServices]).
 * - `.litertlm` model weights are NEVER loaded and multi-GB SHA-256 digests are NEVER computed
 *   synchronously during [onCreate].
 */
open class NavaApplication : Application() {

    @Volatile
    private var _appContainer: AppContainer? = null

    /**
     * Configurable factory hook for [MessageTemplateProvider].
     * Wires [AndroidResourceMessageTemplateProvider] reading `res/values/strings.xml` on Android
     * while allowing testing overrides.
     */
    var templateProviderFactory: (Context) -> MessageTemplateProvider = { ctx ->
        AndroidResourceMessageTemplateProvider(ctx)
    }

    /**
     * Process-wide manual dependency injection container.
     */
    val appContainer: AppContainer
        get() = _appContainer ?: synchronized(this) {
            _appContainer ?: createDefaultContainer().also { _appContainer = it }
        }

    override fun onCreate() {
        super.onCreate()
        val container = appContainer
        runCatching {
            container.bindPlatformServices()
        }
    }

    /**
     * Testing seam allowing Wave 2 UI and Gate 2 Red-Team tests to inject a pre-configured
     * [AppContainer] (e.g. from [AppContainer.createForTesting]).
     */
    fun overrideAppContainerForTesting(container: AppContainer) {
        synchronized(this) {
            _appContainer = container
        }
    }

    protected open fun createDefaultContainer(): AppContainer {
        return AppContainer(
            context = applicationContext,
            templateProviderFactory = templateProviderFactory
        )
    }
}
