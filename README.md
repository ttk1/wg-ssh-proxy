# wg-ssh-proxy

WireGuard 越しに SSH するための `ProxyCommand` 実装。

サーバの公開ポートを WireGuard (UDP) だけに絞れる。WireGuard は正しい鍵を持たない
相手には一切応答しないため、ポートが開いていることすら外部からは観測できず、
より安全な SSH 環境を構築できる。

wireguard-go 公式の [`tun/netstack`](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun/netstack)
をライブラリ利用し、WireGuard をプロセス内のユーザー空間ネットワークスタックで動かす。

- **TUN デバイスを作らない**: OS の仮想 NIC・ルート表・ファイアウォールに一切登場しない。
  外向きは WireGuard の UDP 1 本のみ。常駐プロセスなし、管理者権限不要。
- **完全 split-tunnel**: このプロセスが Dial した SSH の通信だけがトンネルを通る。
  通常のネット通信は無関係。
- **依存は wireguard-go のみ**(gVisor はその推移的依存)。
  配管部分(stdin/stdout ⇄ トンネル内 TCP)は本リポジトリの数百行で、全行読める。

```
ssh myserver ──stdin/stdout──> wg-ssh-proxy ──WireGuard(UDP)──> サーバの wg0 ──> sshd(wg IP のみで listen)
```

## ビルド

ローカルに Go を入れる必要はなく、Docker だけでビルドできる
(Go 環境があれば `make build` 等を直接実行してもよい)。
純 Go (CGO 無効) なので Linux / Windows / macOS いずれもクロスコンパイルできる。

ビルド済みバイナリは配布していないので、以下の手順でビルドして使うこと。

```sh
# Windows 用 exe
docker run --rm -v "${PWD}:/src" -w /src golang:1.25.12 make build-windows

# Linux 用 (golang イメージ内でのビルドは linux/amd64 になる)
docker run --rm -v "${PWD}:/src" -w /src golang:1.25.12 make build

# macOS 用 (クロスコンパイル。Intel Mac は GOARCH=amd64)
docker run --rm -v "${PWD}:/src" -w /src -e GOOS=darwin -e GOARCH=arm64 golang:1.25.12 make build

# テスト (gofmt チェック + go vet + go test)
docker run --rm -v "${PWD}:/src" -w /src golang:1.25.12 make test
```

## セットアップ

以下、例としてサーバ側 wg IP を `10.0.0.1`、クライアント側を `10.0.0.2`、
WireGuard の待受を UDP 51820 とする。

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

- **WireGuard の秘密鍵は設定ファイルでのみ渡す**。コマンドライン引数はプロセス一覧から
  他ユーザーに見えるため、鍵を渡すインターフェース自体を用意していない。
- Unix ではグループ/他ユーザーがアクセス可能なパーミッションだと起動を拒否する
  (`chmod 600` にすること)。Windows では ACL 検査は行わない
  (`%USERPROFILE%` の既定 ACL で保護される前提。共用マシンでは使わないこと)。
- `PresharedKey` の併用を推奨(「今記録して将来解読する」型の攻撃への緩和になる)。

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
消費され `C:Users<user>bin...` のような壊れたパスになる (Windows OpenSSH では
どちらでも動くので、両対応の表記に寄せる)。

## セキュリティ設計

- **暗号は一切自前実装しない**。Noise ハンドシェイク・暗号処理・netstack は
  wireguard-go 公式実装にそのまま委譲し、本リポジトリのコードは
  「設定の読み込み」と「stdin/stdout ⇄ トンネル内 TCP の配管」のみ。
- **秘密鍵はファイル経由でのみ受け取る**(セットアップ 2 参照)。コマンドライン
  引数・環境変数のインターフェースは意図的に用意していない。
- **AllowedIPs は Target の 1 ホストに限定**。WireGuard の cryptokey routing
  により、サーバ側が侵害されてもトンネル内からこちらの netstack へ注入できる
  パケットの送信元は Target の IP 1 つに絞られる(このプロセスが Dial する
  相手は Target だけなので、`0.0.0.0/0` にする理由がない)。
- **待受ソケットを持たず、OS への経路もない**。外向きは WireGuard の UDP 1 本のみで、
  netstack 側でも Listen しない。TUN を作らないため、トンネル側からクライアント OS に
  パケットが届く経路自体が存在しない(ルート表・ファイアウォールも無変更、管理者権限不要)。

## 診断

ログはすべて stderr に出す(stdout は SSH のデータストリームなので汚染しない)。
接続は 15 秒でタイムアウトする。

うまく繋がらない時は `-v` で wireguard-go 内部のログ(ハンドシェイク再送等)を
stderr に出せる:

```
ssh -o ProxyCommand="C:/Users/<user>/bin/wg-ssh-proxy.exe -v" myserver
```

| 終了コード | 意味 |
|---|---|
| 0 | 正常 |
| 1 | 接続失敗 |
| 2 | 設定エラー |

接続失敗時はハンドシェイクの成否で原因を切り分けたメッセージを出す:

- `no WireGuard handshake ...` → 鍵・Endpoint・外向き UDP の疎通を疑う
- `handshake OK but connect ... failed` → Target(サーバの wg IP / sshd ポート)や sshd 側を疑う

## 公開 22 番を閉じる手順(締め出し防止・順序厳守)

1. 本プロキシ経由で SSH 疎通を確認する。
2. ホスティング事業者の Web コンソール(KVM / シリアル)でログインできることを**実際に試す**(最後の命綱)。
3. nftables の新ルールは**時限ロールバック(デッドマン式)**で適用する:
   ```sh
   nft -f /etc/nftables.new.conf && sleep 300 && nft -f /etc/nftables.backup.conf
   ```
   を tmux 内で実行し、別端末から**新ルール越しに**入り直せたら sleep を kill して永続化。
4. 公開 `tcp dport 22` の accept を削除し、`iifname "wg0" tcp dport 22 accept` のみ許可。
5. 最後に sshd の `ListenAddress` を WireGuard インターフェースのサーバ側 IP に絞って再起動する
   (wg 経由の SSH セッションを維持したまま行う)。ブート時に wg0 起動前の bind で失敗しないよう、
   `sshd.service` に `After=wg-quick@wg0.service` の順序依存を追加する。

## 運用メモ

- **外向き UDP を塞ぐネットワーク(ホテル Wi-Fi 等)からは SSH できなくなる**。
  その場合の手段はホスティング事業者の Web コンソールのみ、と割り切る。
- 秘密が SSH 鍵と WireGuard 鍵の 2 つになる。バックアップ・ローテーションは両方を対象にすること。
- NAT が厳しい環境でトンネルが切れる場合のみ `PersistentKeepalive = 25` を設定する。

## 免責事項

- 本リポジトリのコードは AI エージェント (Claude Code) を用いて作成したものです。
- 本ツールの使用によって生じたいかなる損害・結果についても、作者は一切の責任を負いません。
  使用は自己責任でお願いします。
