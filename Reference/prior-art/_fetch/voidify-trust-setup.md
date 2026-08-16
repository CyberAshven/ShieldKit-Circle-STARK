# XI. Trust Setup


***

## English

A Groth16 proving system is only as honest as the randomness used to set it up. Nova's transaction circuit—the circuit that validates flexible deposits, partial withdrawals, nullifiers, and encrypted replacement balances—is verified on-chain against a fixed **verifying key**. Generating that key requires secret randomness, and anyone who retained all of that secret could forge proofs for unauthorized state transitions. The job of a trusted setup ceremony is to make sure that **no one** ends up holding the complete secret.

This chapter describes the public Phase 2 ceremony that produces a Voidify circuit's verifying key, the cryptographic property it relies on, and the artifacts it leaves behind for anyone to audit. Every proof produced for that circuit is verified on-chain against the key created by its ceremony.

{% hint style="info" %}
Nova is the primary circuit covered by the current documentation. Trusted setup remains circuit-specific: Classic withdrawal and Nova's transaction circuit use separate artifacts and verifying keys. Nova's `.wasm`, `.zkey`, and on-chain verifying key must all come from the same audited Nova circuit build.
{% endhint %}

#### Why a Ceremony

Groth16 splits its setup into two phases. Phase 1 — **Powers of Tau** — is circuit-independent and was performed by the public Perpetual Powers of Tau ceremony with thousands of contributors over multiple years. Voidify reuses one of its publicly archived transcripts; we are not re-running Phase 1.

Phase 2 is **circuit-specific**. Once the Nova transaction circuit (`transaction2`) is compiled to its R1CS form, a fresh round of multi-party computation must mix new randomness with the Phase 1 output to produce the final proving and verifying keys for that exact Nova build. This is the round that Voidify asks the public to participate in.

The security property of Phase 2 is unusual and important: **the resulting verifying key is safe so long as a single contributor was honest and erased their entropy**. Not a majority. Not a quorum. One. Every additional contributor only widens the margin. An attacker who wants to break soundness has to compromise — or be — every single person who ever contributed. By the time this ceremony closes, that target list will not be small.

#### How to Contribute

Open the ceremony web app, sign in (GitHub, X, or anonymous), connect a Solana wallet, type a few characters of entropy, and click **Contribute**. Everything cryptographically meaningful happens inside that browser tab. The contributor's secret randomness never leaves the device — it lives only for the duration of one in-browser `snarkjs` call and is gone the moment the tab closes. The published contribution log will then list the wallet address, the optional social handle, and the BLAKE2b-512 hash of the resulting zkey.

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

#### What Anyone Can Check

The ceremony is run by Voidify, but it is not trusted to Voidify. Three properties make the result independently verifiable:

* **Strict chain extension.** The coordinator only accepts a contribution if it extends the existing chain by exactly one new entry, rooted at the same starting state and matching the existing chain entry-for-entry up to that point. Forking from the public genesis and silently overwriting the live chain is not a path the server will follow.
* **Full transcript is public.** The genesis state, the live chain, every archived contribution, and the log mapping each archive to a wallet address and a file hash are all downloadable throughout the ceremony. An auditor can re-walk the chain at any point and confirm that the published final state is the unique result of the published sequence of contributions.
* **Reproducible contribute UI.** The web app is served as a static bundle pinned to IPFS, and a separate verifier repository — [`voidify-ceremony-verifier-frontend`](https://github.com/VoidifyCommunity/voidify-ceremony-verifier-frontend) — builds the same source and emits the IPFS address it would produce. A contributor who reproduces the build for themselves can confirm that the bundle their browser is about to load is exactly the published source — no injected analytics, no hidden upload path that bypasses the local computation.

The first property closes off backend mischief. The second makes any deviation auditable after the fact. The third extends the same audit to the only piece of code with access to the contributor's secret entropy.

If all three hold, the only remaining trust assumption is the one this whole ceremony exists to soften: that **at least one of the contributors honestly discarded their entropy**. That is the entire residual surface.

#### Finalization

When the contribution window closes, a **public-beacon randomness layer** is applied on top of the final chain — typically the hash of a future Bitcoin block, fixed and announced in advance, before its value can be known. The beacon closes the one residual attack the per-contributor model does not close on its own: a contributor who chose their entropy after seeing every transcript before theirs still cannot anticipate a value that did not yet exist when they decided to participate.

The verifying key is then extracted and embedded into the on-chain withdraw verifier by a Solana program redeploy. There is no off-chain switch that swaps the keys quietly: any change to the keys the network verifies against is itself a public on-chain event.

#### Why This Is Enough

Every additional contributor adds one more person an attacker would have to compromise — and even one honest participant is sufficient to make the verifying key sound. Contributing requires no token, no KYC, no social account, no special hardware. The browser does the work, the server records the result, and the public log makes the record permanent.

**One honest contributor is enough — and every contribution after the first only widens the margin.**

***

## 中文

Groth16 证明系统的可信度取决于其设置中使用的随机性。Nova transaction 电路负责验证灵活金额存款、部分提款、nullifier 和加密替代余额，并在链上根据固定的 **verifying key** 进行验证。生成该 key 需要秘密随机数；如果有人保留了完整秘密，就可能为未经授权的状态转换伪造证明。可信设置仪式的任务是确保**没有任何人**最终持有完整秘密。

本章描述为 Voidify 某个电路生成 verifying key 的公开 Phase 2 仪式、它依赖的密码学属性，以及任何人都可以审计的 artifacts。该电路生成的每一份 proof，都会在链上根据对应仪式产生的 key 进行验证。

{% hint style="info" %}
当前文档以 Nova 电路为主要对象。Trusted setup 仍与具体电路绑定：Classic 提款电路与 Nova transaction 电路使用独立 artifacts 和 verifying key。Nova 的 `.wasm`、`.zkey` 和链上 verifying key 必须全部来自同一份经过审计的 Nova 电路构建。
{% endhint %}

#### 为什么需要仪式

Groth16 将设置分为两个阶段。Phase 1，即 **Powers of Tau**，与具体电路无关，已经由公开的 Perpetual Powers of Tau 仪式完成，该仪式在多年间有数千名贡献者参与。Voidify 复用其中一份公开归档的 transcript；我们不会重新运行 Phase 1。

Phase 2 是**电路特定**的。当 Nova transaction 电路（`transaction2`）被编译为 R1CS 后，必须通过新一轮多方计算，把新的随机性与 Phase 1 输出混合，为这一精确的 Nova 构建生成最终 proving key 和 verifying key。这就是 Voidify 邀请公众参与的阶段。

Phase 2 的安全属性很特殊也很重要：**只要有一位贡献者是诚实的，并且删除了自己的熵，最终的 verifying key 就是安全的**。不是多数。不是法定人数。只要一个。每增加一位贡献者，安全余量都会扩大。想破坏 soundness 的攻击者必须攻破，或者本身就是，每一个曾经贡献过的人。当这个仪式结束时，这个目标名单不会很小。

#### 如何贡献

打开 ceremony web app，登录（GitHub、X 或匿名）、连接 Solana 钱包、输入几个字符作为熵，然后点击 **Contribute**。所有具有密码学意义的操作都发生在该浏览器标签页中。贡献者的秘密随机数不会离开设备；它只在一次浏览器内 `snarkjs` 调用期间存在，并在标签页关闭时消失。公开的贡献日志随后会列出钱包地址、可选的社交账号，以及生成 zkey 的 BLAKE2b-512 哈希。

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

#### 任何人都可以检查什么

该仪式由 Voidify 运行，但结果不需要信任 Voidify。三个属性让结果可以被独立验证：

* **严格链式扩展。** Coordinator 只有在某份贡献精确地在现有链上新增一个 entry、根植于同一起始状态，并且到该点为止与已有链逐项匹配时，才会接受它。从公开 genesis 分叉并悄悄覆盖 live chain，并不是服务器会遵循的路径。
* **完整 transcript 公开。** Genesis state、live chain、每份归档贡献，以及将每份 archive 映射到钱包地址和文件哈希的日志，在整个仪式期间都可下载。审计者可以在任何时间重新遍历链，并确认公开的最终状态是公开贡献序列的唯一结果。
* **可复现的贡献 UI。** Web app 以固定到 IPFS 的静态 bundle 提供，另有独立 verifier 仓库 [`voidify-ceremony-verifier-frontend`](https://github.com/VoidifyCommunity/voidify-ceremony-verifier-frontend) 构建相同源码，并输出其会产生的 IPFS 地址。贡献者自行复现构建后，可以确认浏览器即将加载的 bundle 正是公开源码，没有注入 analytics，也没有绕过本地计算的隐藏上传路径。

第一个属性封住后端作恶空间。第二个属性让任何偏离都能在事后审计。第三个属性把同样的审计延伸到唯一能接触贡献者秘密熵的代码。

如果这三点都成立，剩余的唯一信任假设就是整个仪式旨在弱化的那个假设：**至少有一位贡献者诚实地丢弃了自己的熵**。这就是全部剩余攻击面。

#### 最终化

贡献窗口关闭后，会在最终链之上施加一层 **public-beacon randomness**，通常是未来某个 Bitcoin block 的哈希，并且会在其值可知之前提前固定并公布。Beacon 关闭了每个贡献者模型本身无法关闭的一个剩余攻击：即便某个贡献者在看到其之前所有 transcript 后才选择熵，也仍然无法预知一个在其决定参与时尚不存在的值。

随后会提取 verifying key，并通过 Solana program redeploy 嵌入链上 withdraw verifier。不存在可以悄悄替换 keys 的链下开关：网络所依据的验证 keys 发生任何变化，本身都是公开的链上事件。

#### 为什么这足够

每增加一位贡献者，攻击者就多一个必须攻破的人；而即使只有一位诚实参与者，也足以让 verifying key 保持 sound。贡献不需要 token、不需要 KYC、不需要社交账号、不需要特殊硬件。浏览器完成工作，服务器记录结果，公开日志让记录永久存在。

**一位诚实贡献者就足够，而第一位之后的每一次贡献只会进一步扩大安全余量。**

***

## Русский

Надежность Groth16 зависит от randomness, использованной при setup. Nova transaction circuit проверяет flexible deposits, partial withdrawals, nullifiers и encrypted replacement balances по фиксированному ончейн **verifying key**. Для создания key нужна секретная randomness; тот, кто сохранил бы весь секрет, мог бы подделывать proofs для неразрешенных state transitions. Цель trusted setup ceremony — гарантировать, что **никто** не владеет полным секретом.

Эта глава описывает публичную Phase 2 ceremony, создающую verifying key для конкретной circuit Voidify, ее криптографическое свойство и доступные для аудита artifacts. Каждый proof этой circuit проверяется ончейн по key, созданному соответствующей ceremony.

{% hint style="info" %}
Основной объект текущей документации — Nova circuit. Trusted setup остается circuit-specific: Classic withdrawal и Nova transaction circuit используют отдельные artifacts и verifying keys. Nova `.wasm`, `.zkey` и ончейн verifying key должны происходить из одной проверенной сборки Nova circuit.
{% endhint %}

#### Зачем нужна церемония

Groth16 делит настройку на две фазы. Phase 1 — **Powers of Tau** — не зависит от схемы и была выполнена публичной Perpetual Powers of Tau ceremony с тысячами участников за несколько лет. Voidify повторно использует один из ее публично архивированных transcripts; мы не запускаем Phase 1 заново.

Phase 2 является **circuit-specific**. После компиляции Nova transaction circuit (`transaction2`) в R1CS новый раунд multi-party computation смешивает randomness с Phase 1 output и создает proving и verifying keys для этой точной Nova build. Именно в этом раунде Voidify просит общественность участвовать.

Свойство безопасности Phase 2 необычно и важно: **итоговый verifying key безопасен, пока хотя бы один contributor был честен и стер свою entropy**. Не большинство. Не кворум. Один. Каждый дополнительный contributor только расширяет запас прочности. Атакующий, желающий нарушить soundness, должен скомпрометировать — или быть — каждым человеком, который когда-либо внес contribution. К моменту закрытия ceremony этот список целей не будет маленьким.

#### Как внести вклад

Откройте ceremony web app, войдите (GitHub, X или анонимно), подключите Solana wallet, введите несколько символов entropy и нажмите **Contribute**. Все криптографически значимое происходит внутри этой вкладки браузера. Секретная случайность contributor никогда не покидает устройство: она существует только во время одного вызова `snarkjs` в браузере и исчезает в момент закрытия вкладки. Опубликованный contribution log затем покажет wallet address, опциональный social handle и BLAKE2b-512 hash получившегося zkey.

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

#### Что может проверить любой

Ceremony проводится Voidify, но результат не требует доверия к Voidify. Три свойства делают его независимо проверяемым:

* **Строгое расширение цепочки.** Coordinator принимает contribution только если оно расширяет существующую chain ровно на одну новую entry, rooted at the same starting state и совпадает с существующей chain entry-for-entry до этой точки. Форк от публичного genesis с тихой перезаписью live chain — не путь, которому сервер будет следовать.
* **Полный transcript публичен.** Genesis state, live chain, каждая архивированная contribution и log, связывающий каждый archive с wallet address и file hash, доступны для загрузки на протяжении ceremony. Auditor может в любой момент заново пройти chain и подтвердить, что опубликованное final state является уникальным результатом опубликованной последовательности contributions.
* **Воспроизводимый contribute UI.** Web app раздается как static bundle, закрепленный в IPFS, а отдельный verifier repository — [`voidify-ceremony-verifier-frontend`](https://github.com/VoidifyCommunity/voidify-ceremony-verifier-frontend) — собирает тот же source и выводит IPFS address, который он должен произвести. Contributor, который воспроизведет build сам, может убедиться, что bundle, который его браузер собирается загрузить, точно соответствует опубликованному source: без внедренной analytics и без скрытого upload path, обходящего локальное вычисление.

Первое свойство закрывает backend mischief. Второе делает любое отклонение проверяемым постфактум. Третье распространяет тот же аудит на единственный код, имеющий доступ к секретной entropy contributor.

Если все три свойства выполняются, единственное оставшееся trust assumption — то, ради смягчения чего существует вся ceremony: **хотя бы один из contributors честно уничтожил свою entropy**. Это вся остаточная поверхность.

#### Финализация

Когда окно contributions закрывается, поверх final chain применяется слой **public-beacon randomness** — обычно hash будущего Bitcoin block, заранее зафиксированный и объявленный до того, как его значение может быть известно. Beacon закрывает одну остаточную атаку, которую модель per-contributor сама по себе не закрывает: contributor, выбравший entropy после просмотра всех transcripts до него, все равно не может предвидеть значение, которого еще не существовало, когда он решил участвовать.

Затем verifying key извлекается и встраивается в ончейн withdraw verifier через Solana program redeploy. Нет off-chain switch, который тихо меняет keys: любое изменение keys, против которых сеть выполняет verification, само является публичным ончейн-событием.

#### Почему этого достаточно

Каждый дополнительный contributor добавляет еще одного человека, которого атакующему пришлось бы скомпрометировать, и даже одного честного участника достаточно, чтобы verifying key был sound. Contribution не требует token, KYC, social account или специального hardware. Браузер выполняет работу, сервер записывает результат, а public log делает запись постоянной.

**Одного честного contributor достаточно, и каждая contribution после первой только расширяет запас прочности.**

***

## 日本語

Groth16 proving system の信頼性は setup randomness に依存します。Nova transaction circuit は flexible deposits、partial withdrawals、nullifiers、encrypted replacement balances を固定のオンチェーン **verifying key** に対して検証します。Key generation には secret randomness が必要で、完全な secret を保持した者は unauthorized state transition の proof を偽造できる可能性があります。Trusted setup ceremony の目的は、**誰も**完全な secret を保持しないようにすることです。

本章では、Voidify の特定 circuit 用 verifying key を生成する公開 Phase 2 ceremony、その暗号学的性質、そして誰でも監査できる artifacts について説明します。その circuit の各 proof は、対応する ceremony が生成した key に対してオンチェーンで検証されます。

{% hint style="info" %}
現在の documentation は Nova circuit を主要対象とします。Trusted setup は circuit-specific で、Classic withdrawal と Nova transaction circuit は別々の artifacts と verifying keys を使います。Nova の `.wasm`、`.zkey`、on-chain verifying key は同じ監査済み Nova circuit build から生成される必要があります。
{% endhint %}

#### なぜセレモニーが必要か

Groth16 は setup を 2 つの phase に分けます。Phase 1、つまり **Powers of Tau** は circuit-independent であり、複数年にわたる数千人の contributor を伴う公開 Perpetual Powers of Tau ceremony によって実行されました。Voidify は、その公開アーカイブ transcript の 1 つを再利用します。Phase 1 を再実行するわけではありません。

Phase 2 は **circuit-specific** です。Nova transaction circuit（`transaction2`）を R1CS に compile した後、新しい multi-party computation round が randomness と Phase 1 output を混ぜ、その正確な Nova build 用 proving key と verifying key を生成します。Voidify が公開参加を求めるのはこの round です。

Phase 2 の security property は珍しく、重要です。**少なくとも 1 人の contributor が honest で、自分の entropy を削除していれば、結果として得られる verifying key は安全です**。多数派ではありません。Quorum でもありません。1 人です。Contributor が増えるたびに margin は広がります。Soundness を破りたい attacker は、過去に contribution したすべての人物を compromise するか、その全員でなければなりません。この ceremony が閉じる頃、その target list は小さくありません。

#### 貢献方法

Ceremony web app を開き、サインイン（GitHub、X、または anonymous）し、Solana wallet を接続し、数文字の entropy を入力して **Contribute** をクリックします。暗号学的に意味のある処理はすべて、その browser tab 内で行われます。Contributor の秘密 randomness は device から出ません。ブラウザ内の 1 回の `snarkjs` 呼び出しの間だけ存在し、tab を閉じた瞬間に消えます。公開される contribution log には、その後 wallet address、任意の social handle、そして生成された zkey の BLAKE2b-512 hash が記録されます。

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

#### 誰でも確認できること

Ceremony は Voidify によって運営されますが、Voidify を信頼する必要はありません。3 つの性質により、結果は独立に検証できます。

* **厳密な chain extension。** Coordinator は、contribution が既存 chain をちょうど 1 つの新しい entry だけ拡張し、同じ starting state に rooted し、その時点まで既存 chain と entry-for-entry で一致する場合にのみ受け入れます。公開 genesis から fork して live chain を静かに上書きすることは、server が従う path ではありません。
* **Full transcript is public。** Genesis state、live chain、すべての archived contribution、そして各 archive を wallet address と file hash に対応付ける log は、ceremony 中いつでも download できます。Auditor は任意の時点で chain を再度たどり、公開された final state が公開された contribution sequence の一意の結果であることを確認できます。
* **Reproducible contribute UI。** Web app は IPFS に pinned された static bundle として提供され、別の verifier repository [`voidify-ceremony-verifier-frontend`](https://github.com/VoidifyCommunity/voidify-ceremony-verifier-frontend) が同じ source を build し、それが生成する IPFS address を出力します。自分で build を再現した contributor は、browser がこれから読み込む bundle が公開 source そのものであることを確認できます。Injected analytics も、local computation を迂回する hidden upload path もありません。

1 つ目の性質は backend mischief を閉じます。2 つ目は、逸脱があった場合に事後監査できるようにします。3 つ目は、contributor の秘密 entropy にアクセスできる唯一の code に同じ監査を拡張します。

この 3 つがすべて成り立つなら、残る唯一の trust assumption は、この ceremony 全体が和らげるために存在している仮定です。すなわち、**少なくとも 1 人の contributor が自分の entropy を honest に破棄した**ということです。残余 surface はそれだけです。

#### 最終化

Contribution window が閉じると、final chain の上に **public-beacon randomness layer** が適用されます。通常は、値が知られる前にあらかじめ固定・発表された、将来の Bitcoin block の hash です。Beacon は、per-contributor model だけでは閉じられない残余攻撃を閉じます。つまり、ある contributor が自分より前のすべての transcript を見た後に entropy を選んだとしても、参加を決めた時点では存在していなかった値を予測することはできません。

その後 verifying key が抽出され、Solana program redeploy によってオンチェーンの withdraw verifier に埋め込まれます。Keys を静かに入れ替える off-chain switch はありません。ネットワークが検証対象とする keys への変更は、それ自体が公開オンチェーンイベントです。

#### なぜこれで十分か

Contributor が 1 人増えるたびに、attacker が compromise しなければならない人物が 1 人増えます。そして、たった 1 人の honest participant だけで verifying key は sound になります。Contribution には token も、KYC も、social account も、special hardware も不要です。Browser が作業を行い、server が結果を記録し、public log がその記録を永続化します。

**1 人の honest contributor で十分です。そして最初の 1 人以降のすべての contribution は、margin を広げるだけです。**
