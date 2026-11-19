package com.nava.core.ai.locale

import android.content.res.AssetManager
import java.io.File
import java.io.IOException

/**
 * Pure Kotlin abstraction over asset text reading so data-driven locale catalogs and
 * Layer R rule packs work identically on Android (`AssetManager`) and JVM unit tests.
 */
interface AssetTextReader {
    /** Reads UTF-8 text at [relativePath], or returns `null` if the asset does not exist. */
    fun readText(relativePath: String): String?

    /** Lists direct child names inside [relativeDir], or returns an empty list if absent. */
    fun listChildren(relativeDir: String): List<String>
}

/**
 * Production Android implementation backed by [AssetManager].
 */
class AndroidAssetTextReader(
    private val assetManager: AssetManager
) : AssetTextReader {

    override fun readText(relativePath: String): String? {
        val safePath = sanitizeRelativePath(relativePath) ?: return null
        return try {
            assetManager.open(safePath).bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (_: IOException) {
            null
        }
    }

    override fun listChildren(relativeDir: String): List<String> {
        val safeDir = sanitizeRelativePath(relativeDir) ?: return emptyList()
        return try {
            assetManager.list(safeDir)?.sorted() ?: emptyList()
        } catch (_: IOException) {
            emptyList()
        }
    }
}

/**
 * Filesystem directory reader enabling JVM unit tests to load `core-ai/src/main/assets/` directly.
 */
class DirectoryAssetTextReader(
    private val rootDir: File
) : AssetTextReader {

    override fun readText(relativePath: String): String? {
        val target = resolveContained(relativePath) ?: return null
        if (!target.exists() || !target.isFile) return null
        return try {
            target.readText(Charsets.UTF_8)
        } catch (_: IOException) {
            null
        }
    }

    override fun listChildren(relativeDir: String): List<String> {
        val target = resolveContained(relativeDir) ?: return emptyList()
        if (!target.exists() || !target.isDirectory) return emptyList()
        return target.list()?.sorted() ?: emptyList()
    }

    private fun resolveContained(relativePath: String): File? {
        val safePath = sanitizeRelativePath(relativePath) ?: return null
        val rootCanonical = rootDir.canonicalFile
        val candidate = File(rootCanonical, safePath).canonicalFile
        val rootPrefix = rootCanonical.path + File.separator
        return if (candidate.path == rootCanonical.path || candidate.path.startsWith(rootPrefix)) {
            candidate
        } else {
            null
        }
    }
}

/**
 * Classpath resource reader for JVM test environments loading locale assets from test resources.
 */
class ClasspathAssetTextReader(
    private val classLoader: ClassLoader = ClasspathAssetTextReader::class.java.classLoader
        ?: ClassLoader.getSystemClassLoader(),
    private val basePrefix: String = ""
) : AssetTextReader {

    override fun readText(relativePath: String): String? {
        val safePath = sanitizeRelativePath(relativePath) ?: return null
        val fullPath = joinPrefix(safePath)
        val stream = classLoader.getResourceAsStream(fullPath) ?: return null
        return try {
            stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (_: IOException) {
            null
        }
    }

    override fun listChildren(relativeDir: String): List<String> {
        val safeDir = sanitizeRelativePath(relativeDir) ?: return emptyList()
        val fullPath = joinPrefix(safeDir)
        val url = classLoader.getResource(fullPath) ?: return emptyList()
        if (url.protocol != "file") return emptyList()
        val dir = try {
            File(url.toURI())
        } catch (_: Exception) {
            return emptyList()
        }
        return if (dir.exists() && dir.isDirectory) {
            dir.list()?.sorted() ?: emptyList()
        } else {
            emptyList()
        }
    }

    private fun joinPrefix(path: String): String {
        val cleanPrefix = basePrefix.trim('/')
        return if (cleanPrefix.isEmpty()) path else "$cleanPrefix/$path"
    }
}

internal fun sanitizeRelativePath(rawPath: String): String? {
    val trimmed = rawPath.trim()
    if (trimmed.isEmpty()) return null
    if ('\u0000' in trimmed || '\\' in trimmed || trimmed.startsWith('/')) return null
    val segments = trimmed.split('/')
    for (seg in segments) {
        if (seg.isEmpty() || seg == "." || seg == "..") return null
    }
    return trimmed
}
