package com.nava.app.ui.components

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathBuilder
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/**
 * Cached, pure-Compose vector icons (24dp viewport, 1.9dp rounded stroke) with zero external
 * icon-pack dependencies (Iron Law 2).
 */
object NavaIcons {

    private val strokeBrush = SolidColor(Color.Black)
    private const val STROKE_WIDTH = 1.9f

    val HubRing: ImageVector by lazy {
        buildIcon(name = "HubRing") {
            path(
                fill = null,
                stroke = strokeBrush,
                strokeLineWidth = STROKE_WIDTH,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round
            ) {
                circle(cx = 12f, cy = 12f, r = 8.25f)
            }
            path(
                fill = strokeBrush,
                stroke = null
            ) {
                circle(cx = 12f, cy = 12f, r = 2.75f)
            }
        }
    }

    val Shield: ImageVector by lazy {
        strokeIcon(name = "Shield") {
            moveTo(12f, 3f)
            lineTo(19f, 5.8f)
            verticalLineTo(11.4f)
            curveTo(19f, 16.1f, 16.0f, 19.6f, 12f, 21f)
            curveTo(8.0f, 19.6f, 5f, 16.1f, 5f, 11.4f)
            verticalLineTo(5.8f)
            close()
        }
    }

    val Lock: ImageVector by lazy {
        strokeIcon(name = "Lock") {
            // Padlock body
            moveTo(6.5f, 10.5f)
            lineTo(17.5f, 10.5f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 19f, 12f)
            verticalLineTo(19f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = false, isPositiveArc = true, 17f, 21f)
            horizontalLineTo(7f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = false, isPositiveArc = true, 5f, 19f)
            verticalLineTo(12f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 6.5f, 10.5f)
            close()
            // Shackle
            moveTo(8.5f, 10.5f)
            verticalLineTo(7.5f)
            arcTo(3.5f, 3.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 15.5f, 7.5f)
            verticalLineTo(10.5f)
            // Keyhole dot stem
            moveTo(12f, 14.5f)
            verticalLineTo(17f)
        }
    }

    val AuditList: ImageVector by lazy {
        strokeIcon(name = "AuditList") {
            moveTo(6f, 3.5f)
            horizontalLineTo(18f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 19.5f, 5f)
            verticalLineTo(19f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 18f, 20.5f)
            horizontalLineTo(6f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 4.5f, 19f)
            verticalLineTo(5f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 6f, 3.5f)
            close()
            moveTo(8.5f, 8.5f)
            horizontalLineTo(15.5f)
            moveTo(8.5f, 12.2f)
            horizontalLineTo(15.5f)
            moveTo(8.5f, 15.9f)
            horizontalLineTo(13.2f)
        }
    }

    val Bell: ImageVector by lazy {
        strokeIcon(name = "Bell") {
            moveTo(18f, 8.5f)
            arcTo(6f, 6f, 0f, isMoreThanHalf = false, isPositiveArc = false, 6f, 8.5f)
            curveTo(6f, 14.5f, 3.5f, 16.5f, 3.5f, 16.5f)
            horizontalLineTo(20.5f)
            curveTo(20.5f, 16.5f, 18f, 14.5f, 18f, 8.5f)
            moveTo(10.2f, 19.5f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = false, isPositiveArc = false, 13.8f, 19.5f)
        }
    }

    val Moon: ImageVector by lazy {
        strokeIcon(name = "Moon") {
            moveTo(20.2f, 14.6f)
            arcTo(8.2f, 8.2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 9.4f, 3.8f)
            arcTo(6.6f, 6.6f, 0f, isMoreThanHalf = false, isPositiveArc = false, 20.2f, 14.6f)
            close()
        }
    }

    val Sun: ImageVector by lazy {
        strokeIcon(name = "Sun") {
            circle(cx = 12f, cy = 12f, r = 4.2f)
            moveTo(12f, 2.5f)
            verticalLineTo(4.6f)
            moveTo(12f, 19.4f)
            verticalLineTo(21.5f)
            moveTo(2.5f, 12f)
            horizontalLineTo(4.6f)
            moveTo(19.4f, 12f)
            horizontalLineTo(21.5f)
            moveTo(5.3f, 5.3f)
            lineTo(6.8f, 6.8f)
            moveTo(17.2f, 17.2f)
            lineTo(18.7f, 18.7f)
            moveTo(18.7f, 5.3f)
            lineTo(17.2f, 6.8f)
            moveTo(6.8f, 17.2f)
            lineTo(5.3f, 18.7f)
        }
    }

    val Settings: ImageVector by lazy {
        strokeIcon(name = "Settings") {
            circle(cx = 12f, cy = 12f, r = 3.1f)
            moveTo(19.4f, 15f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 19.73f, 16.82f)
            lineTo(19.79f, 16.88f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 16.96f, 19.71f)
            lineTo(16.9f, 19.65f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 15.08f, 19.32f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 14.08f, 20.83f)
            verticalLineTo(21f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 10.08f, 21f)
            verticalLineTo(20.91f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 9f, 19.4f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 7.18f, 19.73f)
            lineTo(7.12f, 19.79f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 4.29f, 16.96f)
            lineTo(4.35f, 16.9f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 4.68f, 15.08f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 3.17f, 14.08f)
            horizontalLineTo(3f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 3f, 10.08f)
            horizontalLineTo(3.09f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 4.6f, 9f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 4.27f, 7.18f)
            lineTo(4.21f, 7.12f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 7.04f, 4.29f)
            lineTo(7.1f, 4.35f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 8.92f, 4.68f)
            horizontalLineTo(9f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 10f, 3.17f)
            verticalLineTo(3f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 14f, 3f)
            verticalLineTo(3.09f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 15f, 4.6f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 16.82f, 4.27f)
            lineTo(16.88f, 4.21f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 19.71f, 7.04f)
            lineTo(19.65f, 7.1f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 19.32f, 8.92f)
            verticalLineTo(9f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 20.83f, 10f)
            horizontalLineTo(21f)
            arcTo(2f, 2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 21f, 14f)
            horizontalLineTo(20.91f)
            arcTo(1.65f, 1.65f, 0f, isMoreThanHalf = false, isPositiveArc = false, 19.4f, 15f)
            close()
        }
    }

    val BackArrow: ImageVector by lazy {
        strokeIcon(name = "BackArrow", autoMirrored = true) {
            moveTo(19f, 12f)
            horizontalLineTo(5f)
            moveTo(11f, 6f)
            lineTo(5f, 12f)
            lineTo(11f, 18f)
        }
    }

    val ChevronRight: ImageVector by lazy {
        strokeIcon(name = "ChevronRight", autoMirrored = true) {
            moveTo(9f, 6f)
            lineTo(15f, 12f)
            lineTo(9f, 18f)
        }
    }

    val FocusMoon: ImageVector by lazy {
        strokeIcon(name = "FocusMoon") {
            moveTo(18.5f, 14.5f)
            arcTo(7.2f, 7.2f, 0f, isMoreThanHalf = true, isPositiveArc = true, 9.5f, 5.5f)
            arcTo(5.6f, 5.6f, 0f, isMoreThanHalf = false, isPositiveArc = false, 18.5f, 14.5f)
            close()
            moveTo(16f, 4.5f)
            verticalLineTo(7.5f)
            moveTo(14.5f, 6f)
            horizontalLineTo(17.5f)
        }
    }

    val Notes: ImageVector by lazy {
        strokeIcon(name = "Notes") {
            moveTo(14f, 3.5f)
            horizontalLineTo(6.5f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = false, 5f, 5f)
            verticalLineTo(19f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = false, 6.5f, 20.5f)
            horizontalLineTo(17.5f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = false, 19f, 19f)
            verticalLineTo(8.5f)
            close()
            moveTo(14f, 3.5f)
            verticalLineTo(8.5f)
            horizontalLineTo(19f)
            moveTo(8.5f, 12.5f)
            horizontalLineTo(15.5f)
            moveTo(8.5f, 16f)
            horizontalLineTo(13.5f)
        }
    }

    val Calendar: ImageVector by lazy {
        strokeIcon(name = "Calendar") {
            moveTo(4f, 6.5f)
            horizontalLineTo(20f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 21.5f, 8f)
            verticalLineTo(19f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 20f, 20.5f)
            horizontalLineTo(4f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 2.5f, 19f)
            verticalLineTo(8f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 4f, 6.5f)
            close()
            moveTo(2.5f, 10.5f)
            horizontalLineTo(21.5f)
            moveTo(8f, 3.5f)
            verticalLineTo(6.5f)
            moveTo(16f, 3.5f)
            verticalLineTo(6.5f)
        }
    }

    val Folder: ImageVector by lazy {
        strokeIcon(name = "Folder") {
            moveTo(3f, 6f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 4.5f, 4.5f)
            horizontalLineTo(9.2f)
            lineTo(11.3f, 7f)
            horizontalLineTo(19.5f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 21f, 8.5f)
            verticalLineTo(18f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 19.5f, 19.5f)
            horizontalLineTo(4.5f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 3f, 18f)
            close()
        }
    }

    val Messages: ImageVector by lazy {
        strokeIcon(name = "Messages") {
            moveTo(4.5f, 4.5f)
            horizontalLineTo(19.5f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 21f, 6f)
            verticalLineTo(15f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 19.5f, 16.5f)
            horizontalLineTo(8.5f)
            lineTo(4f, 20f)
            verticalLineTo(6f)
            arcTo(1.5f, 1.5f, 0f, isMoreThanHalf = false, isPositiveArc = true, 4.5f, 4.5f)
            close()
            moveTo(8f, 9f)
            horizontalLineTo(16f)
            moveTo(8f, 12.2f)
            horizontalLineTo(13f)
        }
    }

    val Clock: ImageVector by lazy {
        strokeIcon(name = "Clock") {
            circle(cx = 12f, cy = 12f, r = 8.5f)
            moveTo(12f, 7.5f)
            verticalLineTo(12f)
            lineTo(15.2f, 14f)
        }
    }

    val Send: ImageVector by lazy {
        strokeIcon(name = "Send", autoMirrored = true) {
            moveTo(20.5f, 3.5f)
            lineTo(10.5f, 13.5f)
            moveTo(20.5f, 3.5f)
            lineTo(14f, 20.5f)
            lineTo(10.5f, 13.5f)
            lineTo(3.5f, 10f)
            close()
        }
    }

    val VoiceSpectrum: ImageVector by lazy {
        strokeIcon(name = "VoiceSpectrum") {
            moveTo(4f, 10f)
            verticalLineTo(14f)
            moveTo(8f, 7f)
            verticalLineTo(17f)
            moveTo(12f, 4.5f)
            verticalLineTo(19.5f)
            moveTo(16f, 7f)
            verticalLineTo(17f)
            moveTo(20f, 10f)
            verticalLineTo(14f)
        }
    }

    val Check: ImageVector by lazy {
        strokeIcon(name = "Check") {
            moveTo(5f, 12.5f)
            lineTo(9.8f, 17.2f)
            lineTo(19f, 7.2f)
        }
    }

    val Close: ImageVector by lazy {
        strokeIcon(name = "Close") {
            moveTo(6f, 6f)
            lineTo(18f, 18f)
            moveTo(18f, 6f)
            lineTo(6f, 18f)
        }
    }

    private inline fun strokeIcon(
        name: String,
        autoMirrored: Boolean = false,
        crossinline block: PathBuilder.() -> Unit
    ): ImageVector {
        return buildIcon(name = name, autoMirrored = autoMirrored) {
            path(
                fill = null,
                stroke = strokeBrush,
                strokeLineWidth = STROKE_WIDTH,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round
            ) {
                block()
            }
        }
    }

    private inline fun buildIcon(
        name: String,
        autoMirrored: Boolean = false,
        block: ImageVector.Builder.() -> Unit
    ): ImageVector {
        return ImageVector.Builder(
            name = name,
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
            autoMirror = autoMirrored
        ).apply(block).build()
    }

    private fun PathBuilder.circle(cx: Float, cy: Float, r: Float) {
        moveTo(cx - r, cy)
        arcToRelative(r, r, 0f, isMoreThanHalf = true, isPositiveArc = false, dx1 = r * 2f, dy1 = 0f)
        arcToRelative(r, r, 0f, isMoreThanHalf = true, isPositiveArc = false, dx1 = -r * 2f, dy1 = 0f)
        close()
    }

    /**
     * Exact geometric outer ring of the Nava brand mark (184x64 viewport matching reference SVG).
     */
    val BrandMarkRing: ImageVector by lazy {
        ImageVector.Builder(
            name = "NavaBrandMarkRing",
            defaultWidth = 75.dp,
            defaultHeight = 26.dp,
            viewportWidth = 184f,
            viewportHeight = 64f
        ).apply {
            path(
                fill = null,
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 3.8f,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round
            ) {
                circle(32f, 32f, 21f)
            }
        }.build()
    }

    /**
     * Exact geometric center dot and "nava" vector wordmark (184x64 viewport matching reference SVG).
     */
    val BrandMarkWordmark: ImageVector by lazy {
        ImageVector.Builder(
            name = "NavaBrandMarkWordmark",
            defaultWidth = 75.dp,
            defaultHeight = 26.dp,
            viewportWidth = 184f,
            viewportHeight = 64f
        ).apply {
            // Center dot
            path(fill = SolidColor(Color.Black)) {
                circle(32f, 32f, 7.5f)
            }
            // Letter 'n'
            path(fill = SolidColor(Color.Black)) {
                moveTo(65f, 21.2f)
                horizontalLineTo(70.1f)
                verticalLineTo(24.3f)
                curveTo(71.8f, 21.9f, 74.5f, 20.5f, 77.9f, 20.5f)
                curveTo(83.7f, 20.5f, 87.6f, 24.4f, 87.6f, 30.8f)
                verticalLineTo(43.2f)
                horizontalLineTo(82.2f)
                verticalLineTo(31.5f)
                curveTo(82.2f, 27.3f, 80.0f, 25.0f, 76.4f, 25.0f)
                curveTo(72.6f, 25.0f, 70.5f, 27.6f, 70.5f, 31.8f)
                verticalLineTo(43.2f)
                horizontalLineTo(65f)
                verticalLineTo(21.2f)
                close()
            }
            // First letter 'a'
            path(
                fill = SolidColor(Color.Black),
                pathFillType = PathFillType.EvenOdd
            ) {
                moveTo(102.2f, 20.5f)
                curveTo(105.8f, 20.5f, 108.7f, 21.9f, 110.4f, 24.1f)
                verticalLineTo(21.2f)
                horizontalLineTo(115.6f)
                verticalLineTo(43.2f)
                horizontalLineTo(110.4f)
                verticalLineTo(40.3f)
                curveTo(108.7f, 42.5f, 105.8f, 43.9f, 102.2f, 43.9f)
                curveTo(95.6f, 43.9f, 90.8f, 38.9f, 90.8f, 32.2f)
                curveTo(90.8f, 25.5f, 95.6f, 20.5f, 102.2f, 20.5f)
                close()
                moveTo(103.3f, 25.0f)
                curveTo(99.0f, 25.0f, 96.2f, 28.0f, 96.2f, 32.2f)
                curveTo(96.2f, 36.4f, 99.0f, 39.4f, 103.3f, 39.4f)
                curveTo(107.6f, 39.4f, 110.4f, 36.4f, 110.4f, 32.2f)
                curveTo(110.4f, 28.0f, 107.6f, 25.0f, 103.3f, 25.0f)
                close()
            }
            // Letter 'v'
            path(fill = SolidColor(Color.Black)) {
                moveTo(118.8f, 21.2f)
                horizontalLineTo(124.6f)
                lineTo(130.8f, 37.6f)
                lineTo(137.0f, 21.2f)
                horizontalLineTo(142.7f)
                lineTo(133.6f, 43.2f)
                horizontalLineTo(128.0f)
                lineTo(118.8f, 21.2f)
                close()
            }
            // Second letter 'a'
            path(
                fill = SolidColor(Color.Black),
                pathFillType = PathFillType.EvenOdd
            ) {
                moveTo(156.2f, 20.5f)
                curveTo(159.8f, 20.5f, 162.7f, 21.9f, 164.4f, 24.1f)
                verticalLineTo(21.2f)
                horizontalLineTo(169.6f)
                verticalLineTo(43.2f)
                horizontalLineTo(164.4f)
                verticalLineTo(40.3f)
                curveTo(162.7f, 42.5f, 159.8f, 43.9f, 156.2f, 43.9f)
                curveTo(149.6f, 43.9f, 144.8f, 38.9f, 144.8f, 32.2f)
                curveTo(144.8f, 25.5f, 149.6f, 20.5f, 156.2f, 20.5f)
                close()
                moveTo(157.3f, 25.0f)
                curveTo(153.0f, 25.0f, 150.2f, 28.0f, 150.2f, 32.2f)
                curveTo(150.2f, 36.4f, 153.0f, 39.4f, 157.3f, 39.4f)
                curveTo(161.6f, 39.4f, 164.4f, 36.4f, 164.4f, 32.2f)
                curveTo(164.4f, 28.0f, 161.6f, 25.0f, 157.3f, 25.0f)
                close()
            }
        }.build()
    }
}
