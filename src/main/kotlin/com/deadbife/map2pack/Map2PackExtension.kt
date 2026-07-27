package com.deadbife.map2pack

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.deadbife.map2pack.ui.Map2PackTab

@Suppress("unused")
class Map2PackExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Map2Pack")

        val config = Config()
        val settings = Settings(api, config)
        settings.load()

        val tab = Map2PackTab(api, config, settings)
        val handler = Map2PackHttpHandler(api, config, tab)

        api.http().registerHttpHandler(handler)
        api.userInterface().registerSuiteTab("Map2Pack", tab.component)

        api.extension().registerUnloadingHandler {
            handler.shutdown()
        }
    }
}
