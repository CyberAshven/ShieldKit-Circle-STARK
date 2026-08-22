---
description: How Voidify Works
---

# II. The Mechanism: Breaking the Link


***

## English

At the core of Voidify’s design are zero-knowledge proofs (zk-SNARKs) and zk-optimized hash functions built to suit Solana’s high-throughput architecture.

#### Nova: The Primary Privacy Mechanism

Nova is Voidify's primary privacy system. It keeps a user's amount inside an encrypted rolling balance rather than forcing each deposit into a fixed denomination. Every deposit or withdrawal consumes the current private output, proves a valid state transition, and creates a new encrypted output for the updated balance.

Because Nova commitments of different amounts share the same token pool, privacy is not split into separate 0.1, 1, 10, or 100-unit buckets. Users can top up a balance, withdraw only part of it, and handle large amounts without waiting for another identical fixed-denomination deposit. Public amounts and timing can still provide correlation clues, but the protocol no longer requires a one-note-to-one-withdrawal pattern.

<figure><img src="https://2312443754-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FDJuzOHtvwNvqd2KgUdyF%2Fuploads%2FMDD8YhvhqGpVn2jmw9pd%2Fvoidify%20astronaut.png?alt=media&#x26;token=f48c2cea-4c25-4fed-98af-29b956398485" alt="" width="275"><figcaption></figcaption></figure>

***

#### Classic Anonymity Pools

Classic remains available as Voidify's fixed-denomination alternative. Each Classic pool accepts one standard deposit amount, such as 0.1 SOL, 1 SOL, or 10 SOL.

A user first deposits into a pool and receives a private note. Later, the user can withdraw the same denomination to a different wallet by generating a zero-knowledge proof. The proof shows that the user owns one valid, unused deposit in the pool, without revealing which deposit it was.

##### Why deposit count matters

More deposits in the same pool create more possible sources for each withdrawal. If a pool has only a few deposits, an observer has fewer candidates to analyze. If a pool has many independent deposits, each withdrawal becomes harder to link to a specific deposit.

For this reason, popular denominations usually provide stronger practical privacy than rarely used denominations.

##### Why timing matters

The time between deposit and withdrawal also affects privacy.

If a user deposits and withdraws shortly afterward, especially when few other deposits happen in between, the withdrawal may be easier to correlate with the recent deposit. Waiting longer allows more deposits to enter the same pool, increasing the number of plausible sources.

A longer delay does not guarantee perfect privacy, but immediate withdrawals usually provide weaker privacy because they create a clearer timing pattern.

This denomination-specific waiting tradeoff applies to Classic. Nova does not require a user— including a large depositor—to wait for another deposit of the exact same amount. Different amounts contribute encrypted commitments to the same token pool, and partial withdrawals let the remainder stay private. Timing still matters, but Nova removes the need to wait solely for a matching denomination.

***

##### **How Deposits Work**

When a user deposits tokens into Voidify:

* A **private note** is generated, containing two random values: a **secret** and a **nullifier**.
* These values are hashed together using the **Poseidon** hash function, creating a **commitment**.
* This commitment is added as a leaf to a Merkle tree stored on-chain.
* The user must store the private note securely, as it will be required to withdraw later.

***

##### **How Withdrawals Work**

To withdraw from the pool:

* The user generates a **zk-proof** that they know a valid, unused commitment in the Merkle tree.
* A **nullifier hash** is submitted, ensuring the commitment cannot be spent twice.
* The smart contract verifies the zk-proof and nullifier.
* If valid, the contract releases the funds to the recipient address.

Since the proof reveals no information about the original commitment’s position in the Merkle tree, and the nullifier cannot be linked back to the deposit, the source of funds remains private.

***

##### **Zero-Knowledge Proofs (zk-Proofs)**

Voidify uses **zk-SNARKs** — succinct, non-interactive cryptographic proofs that verify claims without revealing the underlying data.

* **Privacy**: Proves ownership of a deposit without revealing which one.
* **Security**: Prevents double-spending through nullifier tracking.
* **Efficiency**: Proofs are generated off-chain and verified on-chain.

***

##### ⚙**Poseidon Hash: Optimized for zk-Proofs on Solana**

Voidify uses the **Poseidon hash** instead of older hash functions like Pedersen. This switch dramatically improves performance on Solana:

| Feature                | Pedersen Hash        | Poseidon Hash        |
| ---------------------- | -------------------- | -------------------- |
| zk-Proof Efficiency    | High constraint cost | Minimal constraints  |
| Compatibility          | EVM-optimized        | zk-circuit optimized |
| Cost & Latency         | Expensive            | Fast & cheap         |
| Suitability for Solana | Poor                 | Excellent            |

**Why Poseidon Hash Matters:**

* Reduced computation = faster proof generation
* Optimized for Solana’s low-latency execution
* Lower contract execution cost
* Maintains strong zk-security guarantees

***

##### **Privacy Tips**

To enhance your privacy:

* Use **relayers** to hide your withdrawal origin
* Wait for additional deposits before withdrawing to increase your anonymity set
* Never reuse notes or expose secret values
* Consider different gas parameters and timing for transactions

***

##### **Summary**

Voidify allows you to transact privately on Solana by combining:

* Zero-knowledge cryptography (zk-SNARKs)
* ZK-optimized hashing (Poseidon)
* High-speed, low-cost smart contracts
* A fully self-custodial architecture

The protocol empowers users to move assets without revealing their activity — giving them privacy without compromising security or decentralization.

***

## 中文

Voidify 设计的核心是零知识证明（zk-SNARKs）以及为适配 Solana 高吞吐架构而构建的 zk 优化哈希函数。

#### Nova：主要隐私机制

Nova 是 Voidify 的主要隐私系统。它把金额保存在加密的滚动余额中，而不是强制每笔存款进入固定面额。每次存款或提款都会消费当前私密输出，证明状态转换有效，并为更新后的余额创建新的加密输出。

由于不同金额的 Nova commitments 共享同一代币池，隐私不会被拆分到 0.1、1、10 或 100 等独立面额桶中。用户可以追加余额、只提取部分资金，并处理大额金额而无需等待另一笔完全相同的固定面额存款。公开金额和时间仍可能提供关联线索，但协议不再要求“一份 note 对应一次完整提款”的模式。

<figure><img src="https://2312443754-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FDJuzOHtvwNvqd2KgUdyF%2Fuploads%2FMDD8YhvhqGpVn2jmw9pd%2Fvoidify%20astronaut.png?alt=media&#x26;token=f48c2cea-4c25-4fed-98af-29b956398485" alt="" width="275"><figcaption></figcaption></figure>

***

#### Classic 匿名池

Classic 作为 Voidify 的固定面额备选方式继续保留。每个 Classic 池只接受一种标准存款金额，例如 0.1 SOL、1 SOL 或 10 SOL。

用户首先向某个池存款并获得一份私密 note。之后，用户可以生成零知识证明，将相同面额提取到另一个钱包。该证明表明用户拥有该池中一笔有效且未使用的存款，但不会透露具体是哪一笔。

##### 为什么存款数量重要

同一池中的存款越多，每次提款就有越多可能来源。如果一个池只有少量存款，观察者可分析的候选项就更少。如果一个池有很多独立存款，每次提款就更难被关联到某一笔具体存款。

因此，热门面额通常比很少使用的面额提供更强的实际隐私。

##### 为什么时间间隔重要

存款和提款之间的时间也会影响隐私。

如果用户存款后很快提款，尤其是在中间几乎没有其他存款发生时，该提款更容易与最近的存款相关联。等待更久可以让更多存款进入同一池，从而增加可能来源的数量。

更长的等待并不能保证完美隐私，但立即提款通常隐私较弱，因为它形成了更清晰的时间模式。

这种由面额造成的等待主要适用于 Classic。Nova 不要求用户（包括大额存款用户）等待另一笔完全相同金额的存款。不同金额会向同一代币池贡献加密 commitments，部分提款后剩余余额也可以继续保持私密。时间因素仍然重要，但用户不必仅仅为了等待匹配面额而停留。

***

##### **存款如何工作**

当用户向 Voidify 存入代币时：

* 会生成一份 **private note**，其中包含两个随机值：**secret** 和 **nullifier**。
* 这些值会使用 **Poseidon** 哈希函数一起哈希，生成一个 **commitment**。
* 该 commitment 会作为叶子加入存储在链上的 Merkle tree。
* 用户必须安全保存 private note，因为之后提款需要它。

***

##### **提款如何工作**

从池中提款时：

* 用户生成一个 **zk-proof**，证明自己知道 Merkle tree 中一笔有效且未使用的 commitment。
* 用户提交一个 **nullifier hash**，确保该 commitment 不能被重复花费。
* 智能合约验证 zk-proof 和 nullifier。
* 如果验证有效，合约将资金释放到收款地址。

由于证明不会泄露原始 commitment 在 Merkle tree 中的位置，且 nullifier 不能被反向关联到存款，资金来源保持私密。

***

##### **零知识证明（zk-Proofs）**

Voidify 使用 **zk-SNARKs**，这是一种简洁、非交互式的密码学证明，可以在不泄露底层数据的情况下验证声明。

* **隐私**：证明拥有一笔存款，而不透露是哪一笔。
* **安全**：通过 nullifier 跟踪防止双花。
* **效率**：证明在链下生成，并在链上验证。

***

##### ⚙**Poseidon Hash：为 Solana 上的 zk-Proofs 优化**

Voidify 使用 **Poseidon hash**，而不是 Pedersen 等旧哈希函数。这一切换显著提升了在 Solana 上的性能：

| 特性 | Pedersen Hash | Poseidon Hash |
| --- | --- | --- |
| zk-Proof 效率 | 约束成本高 | 约束极少 |
| 兼容性 | EVM 优化 | zk 电路优化 |
| 成本与延迟 | 昂贵 | 快速且便宜 |
| 对 Solana 的适配 | 较差 | 极佳 |

**为什么 Poseidon Hash 重要：**

* 计算量降低 = 证明生成更快
* 针对 Solana 的低延迟执行优化
* 降低合约执行成本
* 保持强 zk 安全保证

***

##### **隐私建议**

为了增强隐私：

* 使用 **relayers** 隐藏提款来源
* 提款前等待更多存款进入池中，以增加 anonymity set
* 永远不要重复使用 notes 或暴露 secret values
* 考虑不同的 gas 参数和交易时间

***

##### **总结**

Voidify 通过结合以下要素，让你可以在 Solana 上私密交易：

* 零知识密码学（zk-SNARKs）
* ZK 优化哈希（Poseidon）
* 高速、低成本智能合约
* 完全自托管架构

该协议让用户能够在不暴露活动的情况下转移资产，在不牺牲安全性或去中心化的前提下获得隐私。

## Русский

В основе дизайна Voidify лежат доказательства с нулевым разглашением (zk-SNARKs) и zk-оптимизированные хеш-функции, созданные для высокопроизводительной архитектуры Solana.

#### Nova: основной механизм приватности

Nova — основная privacy system Voidify. Сумма хранится как encrypted rolling balance, а не как отдельный fixed denomination. Каждый deposit или withdraw расходует текущий private output, доказывает корректный state transition и создает новый encrypted output с обновленным балансом.

Commitments разных сумм используют один Nova pool для выбранного token, поэтому privacy не разделена на отдельные номиналы 0.1, 1, 10 или 100. Баланс можно пополнять, выводить частично и использовать для крупных сумм без ожидания другого идентичного fixed-denomination deposit. Публичная сумма и timing все еще могут давать подсказки, но протокол больше не требует модели «одна note — один полный вывод».

<figure><img src="https://2312443754-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FDJuzOHtvwNvqd2KgUdyF%2Fuploads%2FMDD8YhvhqGpVn2jmw9pd%2Fvoidify%20astronaut.png?alt=media&#x26;token=f48c2cea-4c25-4fed-98af-29b956398485" alt="" width="275"><figcaption></figcaption></figure>

***

#### Classic-пулы анонимности

Classic остается fixed-denomination альтернативой Voidify. Каждый Classic pool принимает один стандартный размер депозита, например 0.1 SOL, 1 SOL или 10 SOL.

Пользователь сначала вносит средства в пул и получает private note. Позже он может вывести тот же номинал на другой кошелек, сгенерировав zero-knowledge proof. Proof показывает, что пользователь владеет одним действительным неиспользованным депозитом в пуле, не раскрывая каким именно.

##### Почему важен размер пула

Чем больше депозитов в одном пуле, тем больше возможных источников для каждого вывода. Если депозитов мало, у наблюдателя меньше кандидатов для анализа. Если в пуле много независимых депозитов, каждый вывод сложнее связать с конкретным депозитом.

Поэтому популярные номиналы обычно дают более сильную практическую приватность, чем редко используемые.

##### Почему важно время

Время между депозитом и выводом тоже влияет на приватность.

Если пользователь вносит депозит и вскоре выводит средства, особенно если между ними почти не было других депозитов, вывод легче сопоставить с недавним депозитом. Более долгое ожидание позволяет большему числу депозитов войти в тот же пул и увеличивает количество вероятных источников.

Долгая задержка не гарантирует идеальную приватность, но немедленные выводы обычно слабее, потому что создают более ясный временной паттерн.

Это ожидание, связанное с номиналом, относится прежде всего к Classic. В Nova пользователю, включая крупного вкладчика, не нужно ждать другой депозит точно такого же размера. Разные суммы создают encrypted commitments в одном token pool, а partial withdrawal оставляет остаток приватным. Timing по-прежнему важен, но ждать только ради совпадающего номинала не требуется.

***

##### **Как работают депозиты**

Когда пользователь вносит токены в Voidify:

* Генерируется **private note**, содержащая два случайных значения: **secret** и **nullifier**.
* Эти значения хешируются вместе функцией **Poseidon**, создавая **commitment**.
* Commitment добавляется как лист в Merkle tree, хранящееся on-chain.
* Пользователь должен надежно сохранить private note, потому что она потребуется для вывода.

***

##### **Как работают выводы**

Чтобы вывести из пула:

* Пользователь генерирует **zk-proof**, что он знает действительный неиспользованный commitment в Merkle tree.
* Отправляется **nullifier hash**, гарантирующий, что commitment нельзя потратить дважды.
* Smart contract проверяет zk-proof и nullifier.
* Если проверка успешна, контракт отправляет средства получателю.

Так как proof не раскрывает позицию исходного commitment в Merkle tree, а nullifier нельзя связать обратно с депозитом, источник средств остается приватным.

***

##### **Доказательства с нулевым разглашением (zk-Proofs)**

Voidify использует **zk-SNARKs** — краткие неинтерактивные криптографические доказательства, которые проверяют утверждения без раскрытия исходных данных.

* **Privacy**: доказывает владение депозитом, не раскрывая каким.
* **Security**: предотвращает double-spending через отслеживание nullifier.
* **Efficiency**: proofs генерируются off-chain и проверяются on-chain.

***

##### ⚙**Poseidon Hash: оптимизирован для zk-Proofs на Solana**

Voidify использует **Poseidon hash** вместо старых хеш-функций вроде Pedersen. Это резко улучшает производительность на Solana:

| Feature | Pedersen Hash | Poseidon Hash |
| --- | --- | --- |
| zk-Proof Efficiency | высокая стоимость constraints | минимум constraints |
| Compatibility | оптимизирован для EVM | оптимизирован для zk-circuit |
| Cost & Latency | дорого | быстро и дешево |
| Suitability for Solana | плохо | отлично |

**Почему Poseidon Hash важен:**

* меньше вычислений = быстрее proof generation
* оптимизация под низкую задержку Solana
* ниже стоимость исполнения контракта
* сохраняет сильные zk-security guarantees

***

##### **Советы по приватности**

Чтобы усилить приватность:

* Используйте **relayers**, чтобы скрыть источник вывода
* Ждите дополнительных депозитов перед выводом, чтобы увеличить anonymity set
* Никогда не повторно используйте notes и не раскрывайте secret values
* Учитывайте разные gas parameters и timing транзакций

***

##### **Итоги**

Voidify позволяет приватно совершать транзакции на Solana, объединяя:

* zero-knowledge cryptography (zk-SNARKs)
* ZK-optimized hashing (Poseidon)
* быстрые и дешевые smart contracts
* полностью self-custodial architecture

Протокол дает пользователям возможность перемещать активы без раскрытия активности — приватность без компромисса для безопасности или децентрализации.

## 日本語

Voidify の設計の中核には、Solana の高スループット構造に適した zero-knowledge proofs（zk-SNARKs）と zk 最適化ハッシュ関数があります。

#### Nova：主要な Privacy Mechanism

Nova は Voidify の主要な privacy system です。各 deposit を固定額に分けるのではなく、金額を encrypted rolling balance として保持します。Deposit または withdraw のたびに現在の private output を使用し、正しい state transition を証明して、更新残高の新しい encrypted output を作成します。

異なる金額の Nova commitments は同じ token pool を共有するため、privacy は 0.1、1、10、100 などの別々の額面 bucket に分断されません。Balance の top-up、partial withdrawal、大口金額の処理が可能で、同額の fixed-denomination deposit を待つ必要がありません。公開 amount と timing は相関の手掛かりになり得ますが、protocol は「1 note 対 1 full withdrawal」を要求しません。

<figure><img src="https://2312443754-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FDJuzOHtvwNvqd2KgUdyF%2Fuploads%2FMDD8YhvhqGpVn2jmw9pd%2Fvoidify%20astronaut.png?alt=media&#x26;token=f48c2cea-4c25-4fed-98af-29b956398485" alt="" width="275"><figcaption></figcaption></figure>

***

#### Classic 匿名性プール

Classic は Voidify の fixed-denomination alternative として残ります。各 Classic pool は 0.1 SOL、1 SOL、10 SOL など、1 つの標準 deposit amount を受け入れます。

ユーザーはまずプールへ入金し、private note を受け取ります。後で zero-knowledge proof を生成することで、同じ額を別のウォレットへ出金できます。この proof は、ユーザーがプール内の有効で未使用の入金を 1 つ所有していることを示しますが、どの入金かは明かしません。

##### 入金数が重要な理由

同じプール内の入金が多いほど、各出金に対する可能な出所が増えます。プールに少数の入金しかなければ、観察者が分析できる候補は少なくなります。多数の独立した入金があるプールでは、各出金を特定の入金へ結び付けることが難しくなります。

そのため、よく使われる額面は、ほとんど使われない額面よりも実用上強いプライバシーを提供します。

##### タイミングが重要な理由

入金から出金までの時間もプライバシーに影響します。

入金後すぐに出金すると、特にその間に他の入金がほとんどない場合、出金は最近の入金と関連付けられやすくなります。より長く待つことで、同じプールにさらに多くの入金が入り、もっともらしい出所の候補が増えます。

長く待てば完全なプライバシーが保証されるわけではありませんが、即時出金は明確な timing pattern を作るため、通常はプライバシーが弱くなります。

この額面固有の待機は主に Classic に当てはまります。Nova では、大口 depositor を含め、完全に同じ金額の別 deposit を待つ必要はありません。異なる金額が同じ token pool に encrypted commitments を作り、partial withdrawal 後の残高も private に保てます。Timing は依然重要ですが、同額面を待つことだけを理由に長く待つ必要はありません。

***

##### **入金の仕組み**

ユーザーが Voidify にトークンを入金すると：

* **private note** が生成され、そこには 2 つのランダム値 **secret** と **nullifier** が含まれます。
* これらの値は **Poseidon** hash function でまとめてハッシュされ、**commitment** が作られます。
* この commitment はオンチェーンに保存された Merkle tree の leaf として追加されます。
* ユーザーは後の出金に必要な private note を安全に保管する必要があります。

***

##### **出金の仕組み**

プールから出金するには：

* ユーザーは Merkle tree 内の有効で未使用の commitment を知っていることを示す **zk-proof** を生成します。
* **nullifier hash** が提出され、commitment が二重に使われないことを保証します。
* Smart contract が zk-proof と nullifier を検証します。
* 有効であれば、contract は資金を受取アドレスへ解放します。

Proof は元の commitment の Merkle tree 内の位置を一切明かさず、nullifier も入金へ逆に結び付けられないため、資金の出所は private のままです。

***

##### **ゼロ知識証明（zk-Proofs）**

Voidify は **zk-SNARKs** を使用します。これは、基礎データを明かさずに主張を検証する、簡潔で非対話型の暗号学的証明です。

* **Privacy**：どの入金かを明かさずに、入金の所有を証明します。
* **Security**：nullifier tracking によって double-spending を防ぎます。
* **Efficiency**：proofs は off-chain で生成され、on-chain で検証されます。

***

##### ⚙**Poseidon Hash：Solana 上の zk-Proofs に最適化**

Voidify は Pedersen などの古い hash functions ではなく **Poseidon hash** を使います。この変更により Solana 上の性能が大幅に改善されます。

| Feature | Pedersen Hash | Poseidon Hash |
| --- | --- | --- |
| zk-Proof Efficiency | constraint cost が高い | constraints が最小 |
| Compatibility | EVM 最適化 | zk-circuit 最適化 |
| Cost & Latency | 高価 | 高速で安価 |
| Suitability for Solana | 低い | 優秀 |

**Poseidon Hash が重要な理由：**

* 計算量削減 = proof generation が速い
* Solana の低遅延実行に最適化
* contract execution cost を削減
* 強力な zk-security guarantees を維持

***

##### **プライバシーのヒント**

プライバシーを高めるには：

* 出金元を隠すために **relayers** を使う
* anonymity set を増やすため、出金前に追加の入金を待つ
* notes を再利用せず、secret values を公開しない
* transactions の gas parameters と timing を変えることを検討する

***

##### **まとめ**

Voidify は以下を組み合わせることで、Solana 上で private に取引できるようにします。

* zero-knowledge cryptography（zk-SNARKs）
* ZK-optimized hashing（Poseidon）
* 高速・低コスト smart contracts
* 完全な self-custodial architecture

このプロトコルにより、ユーザーは活動を公開せずに資産を移動できます。セキュリティや分散性を犠牲にしないプライバシーを提供します。
