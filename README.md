# wg-ssh-proxy

サーバの sshd を公開ポートから外しても、`ssh myserver` 一発の体験のまま WireGuard 越しに
SSH できるようにする `ProxyCommand` 実装。

wireguard-go 公式の [`tun/netstack`](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun/netstack)
をライブラリ利用し、WireGuard をプロセス内のユーザー空間ネットワークスタックで動かす。

- **TUN デバイスを作らない**: OS の仮想 NIC・ルート表・ファイアウォールに一切登場しない。
  外向きは WireGuard の UDP 1 本のみ。常駐プロセスなし、管理者権限不要。
- **完全 split-tunnel**: このプロセスが Dial した SSH の通信だけがトンネルを通る。
  通常のネット通信は無関係。
- **依存は wireguard-go のみ**(gVisor はその推移的依存)。
  配管部分(stdin/stdout ⇄ トンネル内 TCP)は本リポジトリの数百行で、全行読める。

```
ssh myserver ──stdin/stdout──> wg-ssh-proxy ──WireGuard(UDP)──> サーバの wg1 ──> sshd(wg IP のみで listen)
```

## ビルド

ローカルに Go を入れる必要はなく、Docker だけでビルドできる
(Go 環境があれば `make build` 等を直接実行してもよい)。
依存は `go.sum` で digest 固定、Go バージョンは `go.mod` の `go` ディレクティブで
パッチ版まで固定しているため、同一コミットからは誰がビルドしても同一バイナリになる。

```sh
# Windows 用 exe
docker run --rm -v "${PWD}:/src" -w /src golang:1.25 make build-windows

# Linux / macOS 用
docker run --rm -v "${PWD}:/src" -w /src golang:1.25 make build

# テスト
docker run --rm -v "${PWD}:/src" -w /src golang:1.25 make test
```

### sha256 の生成と検証

```sh
docker run --rm -v "${PWD}:/src" -w /src golang:1.25 sh -c "make build build-windows && sha256sum wg-ssh-proxy wg-ssh-proxy.exe"
```

配布・移動したバイナリは、同一コミットで上を再実行して得たハッシュと一致することを確認する。

## セットアップ

以下、例としてサーバ側 wg IP を `10.0.0.1`、クライアント側を `10.0.0.2`、
WireGuard の待受を UDP 51820 とする。

### 1. サーバ側: SSH 管理専用 WireGuard インターフェース

他用途の WireGuard が既にあっても相乗りせず、**ホストで直接動く SSH 管理専用の
インターフェース**(例: `wg1`)を新設するのを推奨する。特に既存 WireGuard がコンテナ内に
ある場合、相乗りすると「コンテナ侵害 = SSH 経路侵害」の信頼パスができてしまう。

```ini
# /etc/wireguard/wg1.conf
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
  ProxyCommand C:\Users\<user>\bin\wg-ssh-proxy.exe
```

これで `ssh myserver` がそのまま WireGuard 越しになる。

## 診断

ログはすべて stderr に出す(stdout は SSH のデータストリームなので汚染しない)。
接続は 15 秒でタイムアウトする。

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
4. 公開 `tcp dport 22` の accept を削除し、`iifname "wg1" tcp dport 22 accept` のみ許可。
5. 最後に sshd の `ListenAddress` を WireGuard インターフェースのサーバ側 IP に絞って再起動する
   (wg 経由の SSH セッションを維持したまま行う)。ブート時に wg1 起動前の bind で失敗しないよう、
   `sshd.service` に `After=wg-quick@wg1.service` の順序依存を追加する。

## 運用メモ

- **外向き UDP を塞ぐネットワーク(ホテル Wi-Fi 等)からは SSH できなくなる**。
  その場合の手段はホスティング事業者の Web コンソールのみ、と割り切る。
- 秘密が SSH 鍵と WireGuard 鍵の 2 つになる。バックアップ・ローテーションは両方を対象にすること。
- NAT が厳しい環境でトンネルが切れる場合のみ `PersistentKeepalive = 25` を設定する。
