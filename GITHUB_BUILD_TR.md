# GitHub üzerinde V2.6 EXE derleme

1. Bu paketin tüm içeriğini, `.github` dizini dahil, repository ana dizinine yükleyin.
2. Actions > Build YAS BinaryLab X Windows EXE > Run workflow.
3. Başarılı çalışmada Artifacts altında `YAS-BinaryLab-X-Windows-x64` paketini indirin.
4. Hata çıkarsa `cmake-build-diagnostics` içindeki `diagnostics/msvc-build.log` dosyasını paylaşın.

Bu paket yalnızca statik olarak doğrulandı; Windows üzerinde derleme doğrulaması henüz yoktur.
