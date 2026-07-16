# wg-ssh-proxy

WireGuard 越しに SSH するための `ProxyCommand` 実装。

サーバで公開するポートを WireGuard の UDP 1 つだけに絞れる。WireGuard は正しい鍵を
持たない相手には一切応答しないため、外部からはポートが開いていることすら観測できなくなる。

wireguard-go 公式の [`tun/netstack`](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun/netstack)
をライブラリとして利用し、WireGuard をプロセス内のユーザー空間ネットワークスタックで動かす。

- **TUN デバイスを作らない**: OS の仮想 NIC・ルート表・ファイアウォールに一切登場しない。
  外向きは WireGuard の UDP 1 本のみ。常駐プロセスなし、管理者権限不要。
- **完全 split-tunnel**: このプロセスが Dial した SSH の通信だけがトンネルを通り、
  他の通信には一切影響しない。
- **直接依存は wireguard-go と golang.org/x/crypto の 2 つだけ**(x/crypto は
  鍵生成用で、元々 wireguard-go 内部でも使われている。gVisor は推移的依存)。

```
ssh myserver ──stdin/stdout──> wg-ssh-proxy ──WireGuard(UDP)──> サーバの wg0 ──> sshd(wg IP のみで listen)
```

## ビルド

ビルド済みバイナリは配布していないので、以下の手順でビルドして使う。
ローカルに Go を入れる必要はなく、Docker だけでビルドできる
(Go 環境があれば `make build` 等を直接実行してもよい)。
純 Go (CGO 無効) なので Linux / Windows / macOS のどれ向けにもクロスコンパイルできる。

```sh
# Windows 用 exe
docker run --rm -v "${PWD}:/src" -w /src golang:1.25.12 make build-windows

# Linux 用 (golang イメージ内でのビルドは linux/amd64 になる)
docker run --rm -v "${PWD}:/src" -w /src golang:1.25.12 make build

# macOS 用 (クロスコンパイル。Intel Mac は GOARCH=amd64)
docker run --rm -v "${PWD}:/src" -w /src -e GOOS=darwin -e GOARCH=arm64 golang:1.25.12 make build

# テスト (gofmt チェック + go vet + go test)
docker run --rm -v "${PWD}:/src" -w /src golang:1.25.12 make test

# 鍵生成だけ先に済ませたい場合 (バイナリを作らずコンテナ内で直接実行)
docker run --rm -v "${PWD}:/src" -w /src golang:1.25.12 go run ./cmd/wg-ssh-proxy genkey
```

Windows では PowerShell 推奨。Git Bash / MSYS 系シェルで実行する場合はパス変換に注意
(`-v` / `-w` のパスが Windows 形式に書き換えられて失敗する。
`MSYS_NO_PATHCONV=1` を付けるか、パスの先頭を `//` にすると回避できる)。

## セットアップ

以下、例としてサーバ側 wg IP を `10.0.0.1`、クライアント側を `10.0.0.2`、
WireGuard の待受を UDP 51820 とする。

### 0. 鍵の生成

鍵は通常 `wg` コマンドで作るが、WireGuard を入れていないマシン
(典型的には Windows クライアント)では本ツールのサブコマンド
`genkey` / `pubkey` / `genpsk` で代用できる。出力は wg(8) の同名コマンドと互換
(base64 の 32 バイト鍵、1 行)なので、`wg` で作った鍵とそのまま組み合わせられる。

```powershell
# PowerShell の例。> リダイレクトは使わない (PowerShell 5.1 では UTF-16 で
# 書かれてしまう)。Set-Content で書き、Get-Content で読み戻す分には問題ない。
.\wg-ssh-proxy.exe genkey | Set-Content client.key   # 秘密鍵 (画面に出さない)
Get-Content client.key | .\wg-ssh-proxy.exe pubkey   # 公開鍵 (サーバに渡す)
.\wg-ssh-proxy.exe genpsk                            # PSK (両側に書く)
```

```sh
# Linux/macOS の例
umask 077
./wg-ssh-proxy genkey > client.key
./wg-ssh-proxy pubkey < client.key
./wg-ssh-proxy genpsk
```

鍵の対応は次のとおり。PSK だけは対称鍵なので、1 つ作って両側に同じ値を書く:

| 値 | 置き場所 |
|---|---|
| クライアントの秘密鍵 | クライアント config の `PrivateKey` |
| クライアントの公開鍵 | サーバ `[Peer]` の `PublicKey` |
| サーバの秘密鍵 | サーバ `[Interface]` の `PrivateKey` |
| サーバの公開鍵 | クライアント config の `PeerPublicKey` |
| PSK(1 つだけ作る) | クライアント config の `PresharedKey` とサーバ `[Peer]` の `PresharedKey` |

### 1. サーバ側: WireGuard インターフェース

サーバに SSH 用の WireGuard インターフェース(例: `wg0`)を用意する:

```ini
# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = <サーバの秘密鍵 (wg genkey)>
Address    = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey    = <クライアントの公開鍵>
# PresharedKey = <wg genpsk の出力(推奨)>
AllowedIPs   = 10.0.0.2/32
```

サーバ側に `PersistentKeepalive` は不要(クライアントが Dial 起点のため)。

### 2. クライアント側: 設定ファイル

`%USERPROFILE%\.wg-ssh\config`(Linux/macOS: `~/.wg-ssh/config`)に配置する。
別の場所に置く場合は `-config <パス>` で指定できる。
サンプル: [examples/wg-ssh-proxy.conf.example](examples/wg-ssh-proxy.conf.example)

- **秘密鍵はこの設定ファイルでのみ渡す**。コマンドライン引数や環境変数では
  渡せない(理由は後述のセキュリティ設計を参照)。
- Unix では、グループ/他ユーザーがアクセス可能なパーミッションだと起動を拒否する
  (`chmod 600` にすること)。Windows では ACL 検査は行わず、`%USERPROFILE%` の
  既定 ACL で保護される前提とする(共用マシンでは使わないこと)。
- `PresharedKey` の併用を推奨(「今記録して将来解読する」型の攻撃への緩和策になる)。

### 3. クライアント側: ~/.ssh/config

サンプル: [examples/ssh_config.example](examples/ssh_config.example)

```
Host myserver
  HostName 10.0.0.1
  ProxyCommand C:/Users/<user>/bin/wg-ssh-proxy.exe
```

これで `ssh myserver` がそのまま WireGuard 越しになる。

Windows でもパスは**フォワードスラッシュ表記**にすること。`ProxyCommand` はシェル経由で
実行されるため、Git Bash / MSYS 系の ssh ではバックスラッシュがエスケープとして
消費され、`C:Users<user>bin...` のような壊れたパスになる(Windows OpenSSH は
どちらの表記でも動くので、両対応のフォワードスラッシュに寄せる)。

## セキュリティ設計

- **暗号は一切自前実装しない**。Noise ハンドシェイク・暗号処理・netstack は
  wireguard-go 公式実装にそのまま委譲する。本リポジトリ自体のコードは
  「設定の読み込み」と「stdin/stdout ⇄ トンネル内 TCP の配管」だけの数百行で、
  全部読み切れる分量に収めている。
- **秘密鍵はファイル経由でのみ受け取る**。コマンドライン引数・環境変数の
  インターフェースは意図的に用意していない。引数で渡す形にすると鍵がプロセス一覧から
  他ユーザーに見えてしまうためで、`pubkey` サブコマンドも `wg pubkey` と同様に
  標準入力から受け取る。
- **AllowedIPs は Target の 1 ホストに限定**。WireGuard の cryptokey routing により、
  サーバ側が侵害されても、トンネル内からクライアントの netstack へ注入できるパケットの
  送信元は Target の IP 1 つに絞られる(このプロセスが Dial する相手は Target
  だけなので、`0.0.0.0/0` にする理由がない)。
- **待受ソケットを持たない**。netstack 側でも Listen せず、TUN デバイスも無いため、
  トンネル側からクライアント OS にパケットが届く経路自体が存在しない。

## 診断

ログはすべて stderr に出す(stdout は SSH のデータストリームなので汚染しない)。

うまく繋がらない時は `-v` で wireguard-go 内部のログ(ハンドシェイク再送等)を
stderr に出せる:

```
ssh -o ProxyCommand="C:/Users/<user>/bin/wg-ssh-proxy.exe -v" myserver
```

| 終了コード | 意味 |
|---|---|
| 0 | 正常 |
| 1 | 接続失敗 |
| 2 | 設定・使い方のエラー |

接続は 15 秒でタイムアウトし、ハンドシェイクの成否で原因を切り分けたメッセージを出す:

- `no WireGuard handshake ...` → 鍵・Endpoint・外向き UDP の疎通を疑う
- `handshake OK but connect ... failed` → Target(サーバの wg IP / sshd ポート)や sshd 側を疑う

## 公開 22 番を閉じる手順(締め出し防止・順序厳守)

閉じ方は環境に応じて 2 通り。**基盤側にファイアウォール(クラウドの
セキュリティグループ等)があれば A、無ければ B** を採る。A は基盤側で閉じるため
パケットがホストに到達せず、ホスト内 nftables のロード失敗や順序ミスがあっても
「うっかり開く」方向には倒れない。復旧も管理画面から 22 の許可を戻すだけで済み、
nftables を操作できないまま身動きが取れなくなる事態もない。
どちらの場合も、ホスト側 nftables は二重防御として残す。

共通の事前確認(どちらの方式でも必須):

1. 本プロキシ経由で SSH 疎通を確認する。
2. ホスティング事業者の Web コンソール(KVM / シリアル)でログインできることを**実際に試す**(最後の命綱)。

### A. 基盤側ファイアウォールで閉じる

3. **先に WireGuard の UDP 許可が基盤側に入っていることを確認する**(対象は SSH 用
   wg の ListenPort。SSH 用のルールテンプレートは TCP/22 しか開けていないことが多く、
   UDP を明示的に許可しないまま 22 を外すと、その瞬間に wg も通らなくなり完全に
   締め出される)。
4. 基盤側から **TCP/22 の許可を外す**(拒否ルールを足すのではなく、許可リストから
   22 を削除する操作になることが多い)。
5. 外部から `nc -vz <host> 22` が失敗し、本プロキシ経由の SSH は生きていることを確認する。
6. ホスト側 nftables はそのまま残す。

### B. ホスト nftables で閉じる

3. nftables の新ルールは**時限ロールバック(デッドマン式)**で適用する:
   ```sh
   nft -f /etc/nftables.new.conf && sleep 300 && nft -f /etc/nftables.backup.conf
   ```
   を tmux 内で実行し、別端末から**新ルール越しに**入り直せたら sleep を kill して永続化。
4. 公開 `tcp dport 22` の accept を削除し、`iifname "wg0" tcp dport 22 accept` のみ許可。

## 運用メモ

- **同じ設定(= 同じ鍵)での同時接続は 1 本に保つこと**。接続ごとに独立した
  WireGuard トンネルができるが、サーバから見ればどれも同一 peer なので、複数同時に
  張るとセッションを取り合い、互いに断続的に十数秒フリーズする。SFTP ブラウザ用
  などに裏で 2 本目の接続を張るクライアントツールでは、その機能を無効にすること。
- **外向き UDP を塞ぐネットワーク(ホテル Wi-Fi 等)からは SSH できなくなる**。
  その場合の手段はホスティング事業者の Web コンソールのみ、と割り切る。
- 守るべき秘密鍵が SSH と WireGuard の 2 つになる。バックアップ・ローテーションは両方を対象にすること。
- NAT が厳しい環境でトンネルが切れる場合のみ `PersistentKeepalive = 25` を設定する。

## 免責事項

- 本リポジトリのコードは AI エージェント (Claude Code) を用いて作成したものです。
- 本ツールの使用によって生じたいかなる損害・結果についても、作者は一切の責任を負いません。
  使用は自己責任でお願いします。
