[app]
title = LuVex Scanner
package.name = luvexscanner
package.domain = ir.luvexmc
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,ttf
version = 1.1
requirements = python3,kivy==2.3.0,pyjnius,dnspython,arabic-reshaper==3.0.0,python-bidi==0.4.2,six
orientation = portrait, landscape
fullscreen = 0

android.permissions = INTERNET,WRITE_EXTERNAL_STORAGE
android.api = 33
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
