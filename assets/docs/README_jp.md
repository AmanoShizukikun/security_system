# security_system

[![GitHub Repo stars](https://img.shields.io/github/stars/AmanoShizukikun/security_system?style=social)](https://github.com/AmanoShizukikun/security_system/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/AmanoShizukikun/security_system)](https://github.com/AmanoShizukikun/security_system/commits/main)
[![GitHub release](https://img.shields.io/github/v/release/AmanoShizukikun/security_system)](https://github.com/AmanoShizukikun/security_system/releases)

\[ [中文](https://github.com/AmanoShizukikun/security_system/blob/main/README.md) | [English](https://github.com/AmanoShizukikun/security_system/blob/main/assets/docs/README_en.md) | 日本語 \]

## 概要
勤益科技大学 Web プログラミング期末レポート「セキュリティインシデント通報システム」。
![t2i](https://github.com/AmanoShizukikun/security_system/blob/main/assets/preview/preview.png)

## 最近の変更
### 1.0.0 (2025年6月8日)
### 重要な変更
- 【重大】初回リリース版。
### 新機能
- N/A
### 既知の問題
- N/A

[すべてのリリース](https://github.com/AmanoShizukikun/security_system/blob/main/assets/docs/Changelog.md)

## クイックスタート
> [!NOTE]
> これは必須手順です。
### 環境設定
- **Python 3**
  - ダウンロード: https://www.python.org/downloads/windows/
- **SQLite**
  - ダウンロード: https://sqlite.org/download.html

### リポジトリのインストール
> [!IMPORTANT]
> これは必須手順です。
```shell
git clone https://github.com/AmanoShizukikun/security_system.git
cd security_system
pip install -r requirements.txt
```

### Webアプリケーションの起動
```shell
flask --debug run
```

## システムデモ
<div align="center">
  <a href="https://youtu.be/FcvB6M-iEws?si=QUaJgNEo6I91XWcz" target="_blank">
    <img src="https://img.youtube.com/vi/FcvB6M-iEws/maxresdefault.jpg" 
         alt="セキュリティインシデント通報システムデモ動画" 
         width="80%" 
         style="border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
  </a>
</div>

## TODO リスト
- **高優先度：**
  - [x] クイックインストールガイド。
  - [ ] 使用ガイド(wiki)。

- **機能:**
  - データベース
    - [x] プログラム初回起動時に security_incidents.db と members テーブルを作成し、レコードを追加。
    
  - プログラム
    - [x] ホームページ。
    - [x] 登録ページ。
    - [x] ログインページ。

## 謝辞
以下のプロジェクトと貢献者に特別な感謝を：

### プロジェクト
N/A

### 貢献者
<a href="https://github.com/AmanoShizukikun/security_system/graphs/contributors" target="_blank">
  <img src="https://contrib.rocks/image?repo=AmanoShizukikun/security_system" />
</a>