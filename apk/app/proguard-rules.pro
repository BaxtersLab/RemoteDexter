# ProGuard rules for RemoteDexter
# Keep JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Kotlin companion objects used by JNI
-keep class com.remotedexter.RDRust { *; }
-keep class com.remotedexter.TransportBindings { *; }
-keep class com.remotedexter.ClipboardBindings { *; }
-keep class com.remotedexter.ScreenshotBindings { *; }
-keep class com.remotedexter.PowerBindings { *; }
-keep class com.remotedexter.MediaBindings { *; }
-keep class com.remotedexter.Agent2Bindings { *; }
