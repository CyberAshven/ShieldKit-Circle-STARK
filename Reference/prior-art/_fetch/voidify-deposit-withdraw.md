---
description: How to Deposit & Withdraw Using Voidify
---

# V. Deposit & Withdraw


***

## English

Voidify's primary deposit and withdrawal experience is the flexible-amount [**Nova Privacy Pool**](iii.-nova-privacy-pool.md). Nova supports balance top-ups, partial withdrawals, and large deposits without requiring another deposit of the exact same denomination. Fixed-denomination **Classic** pools remain available as an alternative workflow.

**Nova Deposit Guide**

1. Connect a supported Solana wallet and open the **Nova** page.

    <figure><img src=".gitbook/assets/image copy.png" alt=""><figcaption></figcaption></figure>

2. Select an available token and unlock the Nova key. The wallet signs an off-chain message; this does not send a transaction or spend SOL.

    <figure><img src=".gitbook/assets/image copy 6.png" alt=""><figcaption></figcaption></figure>

3. Optionally enter a passphrase. Always use the exact same wallet and passphrase to reopen this Nova balance.

    <figure><img src=".gitbook/assets/image copy 2.png" alt=""><figcaption></figcaption></figure>

4. Enter any supported positive amount within the pool's current limits, then review and confirm the deposit.

    <figure><img src=".gitbook/assets/image copy 3.png" alt=""><figcaption></figcaption></figure>

    <figure><img src=".gitbook/assets/image copy 7.png" alt=""><figcaption></figcaption></figure>

5. Keep the page open while Nova synchronizes commitments, generates the proof locally, and submits the transaction.

The new amount is added to the existing private balance. There is no need to create or manage a separate fixed-denomination note for every deposit.

**Nova Withdraw Guide**

1. Connect the original wallet, unlock Nova with the same passphrase, and select the token.
2. Wait for the private balance to synchronize, then enter any amount up to the available balance.
3. Enter the recipient address and review the selected relayer, relayer fee, and treasury fee.

    <figure><img src=".gitbook/assets/image copy 4.png" alt=""><figcaption></figcaption></figure>

4. Confirm the withdrawal. Nova generates a zero-knowledge proof and the relayer submits it on-chain.

    <figure><img src=".gitbook/assets/image copy 5.png" alt=""><figcaption></figcaption></figure>

5. The requested amount is withdrawn, while any remainder is committed to a new encrypted Nova output and stays private.

{% hint style="success" %}
Nova has no protocol-enforced waiting period and does not require another user to deposit the exact same amount. Even a large balance can be withdrawn in parts. More unrelated activity can still improve practical privacy, so avoid an immediate withdrawal with a highly distinctive public amount when your threat model requires stronger protection.
{% endhint %}

The remainder of this chapter documents the optional Classic workflow.

**Classic Deposit Guide**

**1. Connect Your Wallet**

Click **Connect** and choose a Solana-compatible wallet such as:

* ✅ Phantom
* ✅ Solflare
* ✅ Metamask

Ensure you're connected to **Solana Mainnet**.

***

**2. Select a Token & Amount**

Choose the token you want to deposit (**SOL**) and the corresponding **fixed-denomination pool** (e.g., 1 SOL, 10 SOL,).

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Standardized pool sizes help protect privacy by eliminating unique transaction fingerprints.
{% endhint %}

***

**3. Generate and Secure Your Note**

Click deposit:

* A **private note** will be generated in your browser.
*   This note proves you deposited — and is required to withdraw later.

    <figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

> ⚠️ **Important**: Save your note securely.\
> Voidify does not store it. If you lose it, your funds are irrecoverable.

**Do not store notes in:**

* Unencrypted devices
* Browsers or autofill
* Cloud storage or chat apps

***

**4. Confirm Deposit**

Once you've saved the note:

* Click **Confirm**
* Approve the transaction in your wallet
* Your funds will be added to the on-chain privacy pool

***

**5. Wait to Strengthen Privacy**

Withdrawing immediately weakens your anonymity.\
To increase your privacy:

* Wait for more users to deposit into the same pool
* Larger **anonymity sets** reduce correlation risk

You’ll be able to monitor pool activity in the **Anonymity Set Dashboard**.

{% hint style="info" %}
This waiting rule is denomination-specific to Classic. With [Nova](iii.-nova-privacy-pool.md), you do not need to wait for another deposit of the exact same amount—even for a large balance—and you can withdraw only part of the balance.
{% endhint %}

***

**Classic Withdraw Guide**

**1. Connect Wallet & Select Pool**\
Click **Connect** → Choose your wallet → Navigate to the **Withdraw** tab.

***

**2. Paste Your Private Note and Recipient Address**\
Paste your saved note and recipient address into the withdrawal field.

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

> This cryptographically proves you made a deposit — without revealing which one.

***

**3. Choose a Relayer (opeitonal, Because the system will automatically choose)**

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

* Select a **relayer** to submit the withdrawal transaction on your behalf

***

**4. Click Withdraw**

* **Click Withdraw**
*   Click **Confirm**

    <figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

> The funds will be sent to your selected address without any visible on-chain link to your deposit.

***

**Optional: Note Account (Coming Soon)**

Voidify is building a secure **on-chain backup feature** called the **Note Account**.\
This will allow you to store encrypted notes without relying on off-chain tools.

> ⚠️ Use caution: if your backup key is ever compromised, your deposits can be deanonymized.\
> Only use this feature if you fully understand the tradeoffs.

***

**Never Share Your Note**

Your private note is your key to withdraw funds.\
If anyone accesses it, they can withdraw your deposit.

* ❌ Don’t screenshot it
* ❌ Don’t store in cloud apps
* ❌ Don’t paste in browsers or shared devices

> Losing your note = permanent loss of access.

***

**Classic Summary**

* Use a supported Solana wallet
* Choose a fixed pool size
* Save your private note securely
* For Classic, wait for activity in the same denomination before withdrawing
* Use a relayer to protect your withdrawal identity
* Never reuse wallets
* Never share your private note

Voidify gives you cryptographic privacy.\
Protecting it is your responsibility.

***

## 中文

Voidify 的主要存取款方式是灵活金额的 [**Nova 隐私池**](iii.-nova-privacy-pool.md)。Nova 支持追加余额、部分提款和大额存款，而且不要求等待另一笔完全相同面额的存款。固定面额 **Classic** 池作为备选方式继续保留。

**Nova 存款指南**

1. 连接兼容的 Solana 钱包并打开 **Nova** 页面。

    <figure><img src=".gitbook/assets/image copy.png" alt=""><figcaption></figcaption></figure>

2. 选择可用代币并解锁 Nova 密钥。钱包只签署一条链下消息，不会发送交易或消耗 SOL。

    <figure><img src=".gitbook/assets/image copy 6.png" alt=""><figcaption></figcaption></figure>

3. 可选填写 passphrase。之后必须使用完全相同的钱包和 passphrase 才能重新打开这份 Nova 余额。

    <figure><img src=".gitbook/assets/image copy 2.png" alt=""><figcaption></figcaption></figure>

4. 输入池当前限制范围内的任意正数金额，核对后确认存款。

    <figure><img src=".gitbook/assets/image copy 3.png" alt=""><figcaption></figcaption></figure>

    <figure><img src=".gitbook/assets/image copy 7.png" alt=""><figcaption></figcaption></figure>

5. Nova 同步 commitments、在本地生成证明并提交交易时，请保持页面打开。

新金额会直接加入现有私密余额，无需为每次存款创建和管理单独的固定面额 note。

**Nova 提款指南**

1. 连接原钱包，使用相同 passphrase 解锁 Nova，并选择代币。
2. 等待私密余额同步，然后输入不超过可用余额的任意提款金额。
3. 填写收款地址，并核对所选 relayer、relayer fee 和 treasury fee。

    <figure><img src=".gitbook/assets/image copy 4.png" alt=""><figcaption></figcaption></figure>

4. 确认提款。Nova 生成零知识证明，并由 relayer 提交到链上。

    <figure><img src=".gitbook/assets/image copy 5.png" alt=""><figcaption></figcaption></figure>

5. 请求金额被提取后，剩余余额会进入新的加密 Nova 输出并继续保持私密。

{% hint style="success" %}
Nova 没有协议强制等待期，也不要求另一位用户存入完全相同的金额。即使是大额余额，也可以分批提取。更多无关活动仍可能提升实际隐私；如果威胁模型要求更强保护，应避免立即提取非常独特的公开金额。
{% endhint %}

本章其余部分介绍可选的 Classic 操作方式。

**Classic 存款指南**

**1. 连接你的钱包**

点击 **Connect**，并选择兼容 Solana 的钱包，例如：

* ✅ Phantom
* ✅ Solflare
* ✅ Metamask

确保你连接的是 **Solana Mainnet**。

***

**2. 选择代币和金额**

选择要存入的代币（**SOL**）以及对应的**固定面额池**，例如 1 SOL、10 SOL。

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
标准化的池子面额有助于消除独特的交易指纹，从而保护隐私。
{% endhint %}

***

**3. 生成并保护你的 Note**

点击 deposit：

* 浏览器会生成一份**私密 note**。
* 这份 note 用来证明你已存款，并且之后提款必须使用它。

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

> ⚠️ **重要**：请安全保存你的 note。\
> Voidify 不会保存它。如果遗失，资金将无法找回。

**不要把 note 存放在：**

* 未加密设备中
* 浏览器或自动填充工具中
* 云存储或聊天应用中

***

**4. 确认存款**

保存 note 后：

* 点击 **Confirm**
* 在钱包中批准交易
* 你的资金将被加入链上隐私池

***

**5. 等待以增强隐私**

立即提款会削弱你的匿名性。\
为了提高隐私：

* 等待更多用户向同一个池子存款
* 更大的**匿名集**会降低关联风险

你可以在 **Anonymity Set Dashboard** 中监控池子活动。

{% hint style="info" %}
这种等待规则主要针对按面额划分的 Classic 池。使用 [Nova](iii.-nova-privacy-pool.md) 时，即使是大额余额，也不需要等待另一笔完全相同金额的存款，并且可以只提取部分余额。
{% endhint %}

***

**Classic 提款指南**

**1. 连接钱包并选择池子**\
点击 **Connect** → 选择你的钱包 → 进入 **Withdraw** 标签页。

***

**2. 粘贴你的私密 Note 和收款地址**\
将保存好的 note 与收款地址粘贴到提款字段中。

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

> 这会以密码学方式证明你曾经存款，但不会透露是哪一笔存款。

***

**3. 选择 Relayer（可选，因为系统会自动选择）**

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

* 选择一个 **relayer**，由它代表你提交提款交易

***

**4. 点击 Withdraw**

* 点击 **Withdraw**
* 点击 **Confirm**

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

> 资金会发送到你选择的地址，并且链上不会出现与存款之间的可见关联。

***

**可选：Note Account（即将推出）**

Voidify 正在构建一个安全的**链上备份功能**，称为 **Note Account**。\
它将允许你保存加密后的 note，而不必依赖链下工具。

> ⚠️ 请谨慎使用：如果你的备份密钥被泄露，你的存款可能被去匿名化。\
> 只有在完全理解取舍后才使用此功能。

***

**绝不要分享你的 Note**

你的私密 note 是提款资金的钥匙。\
任何获得它的人都可以取走你的存款。

* ❌ 不要截图
* ❌ 不要存入云应用
* ❌ 不要粘贴到浏览器或共享设备中

> 丢失 note = 永久失去访问权限。

***

**Classic 总结**

* 使用受支持的 Solana 钱包
* 选择固定池子面额
* 安全保存你的私密 note
* 使用 Classic 时，提款前等待同一面额池出现更多活动
* 使用 relayer 保护你的提款身份
* 绝不重复使用钱包
* 绝不分享你的私密 note

Voidify 为你提供密码学隐私。\
保护它是你的责任。

***

## Русский

Основной режим deposit и withdraw в Voidify — [**Nova Privacy Pool**](iii.-nova-privacy-pool.md) с гибкими суммами. Nova поддерживает пополнение баланса, partial withdrawals и крупные депозиты без ожидания другой суммы точно того же номинала. Fixed-denomination **Classic** остается альтернативой.

**Руководство по депозиту Nova**

1. Подключите Solana wallet и откройте страницу **Nova**.

    <figure><img src=".gitbook/assets/image copy.png" alt=""><figcaption></figcaption></figure>

2. Выберите token и разблокируйте Nova key. Wallet подписывает off-chain message без транзакции и расхода SOL.

    <figure><img src=".gitbook/assets/image copy 6.png" alt=""><figcaption></figcaption></figure>

3. При желании задайте passphrase. Для повторного открытия баланса нужны тот же wallet и точная passphrase.

    <figure><img src=".gitbook/assets/image copy 2.png" alt=""><figcaption></figcaption></figure>

4. Введите любую положительную сумму в пределах текущих pool limits и подтвердите депозит.

    <figure><img src=".gitbook/assets/image copy 3.png" alt=""><figcaption></figcaption></figure>

    <figure><img src=".gitbook/assets/image copy 7.png" alt=""><figcaption></figcaption></figure>

5. Не закрывайте страницу во время синхронизации commitments, локальной генерации proof и отправки транзакции.

Новая сумма добавляется к существующему private balance; отдельная fixed-denomination note для каждого депозита не нужна.

**Руководство по выводу Nova**

1. Подключите исходный wallet, разблокируйте Nova с той же passphrase и выберите token.
2. Дождитесь синхронизации и введите любую сумму не больше доступного баланса.
3. Укажите recipient и проверьте relayer, relayer fee и treasury fee.

    <figure><img src=".gitbook/assets/image copy 4.png" alt=""><figcaption></figcaption></figure>

4. Подтвердите вывод. Nova создает proof, а relayer отправляет его ончейн.

    <figure><img src=".gitbook/assets/image copy 5.png" alt=""><figcaption></figcaption></figure>

5. Остаток записывается в новый encrypted Nova output и остается приватным.

{% hint style="success" %}
В Nova нет обязательного периода ожидания и не нужен другой депозит точно такого же размера. Крупный баланс можно выводить частями. Дополнительная независимая активность все равно может улучшить privacy, поэтому при сильном threat model избегайте немедленного вывода уникальной публичной суммы.
{% endhint %}

Остальная часть главы описывает альтернативный Classic workflow.

**Руководство по депозиту Classic**

**1. Подключите кошелек**

Нажмите **Connect** и выберите совместимый с Solana кошелек, например:

* ✅ Phantom
* ✅ Solflare
* ✅ Metamask

Убедитесь, что вы подключены к **Solana Mainnet**.

***

**2. Выберите токен и сумму**

Выберите токен для депозита (**SOL**) и соответствующий **пул фиксированного номинала** (например, 1 SOL, 10 SOL).

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Стандартизированные размеры пулов помогают защищать приватность, устраняя уникальные транзакционные отпечатки.
{% endhint %}

***

**3. Создайте и защитите свою Note**

Нажмите deposit:

* В браузере будет создана **приватная note**.
* Эта note доказывает, что вы внесли депозит, и требуется для последующего вывода.

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

> ⚠️ **Важно**: надежно сохраните свою note.\
> Voidify не хранит ее. Если вы ее потеряете, средства невозможно будет восстановить.

**Не храните notes в:**

* незашифрованных устройствах;
* браузерах или автозаполнении;
* облачных хранилищах или чат-приложениях.

***

**4. Подтвердите депозит**

После сохранения note:

* нажмите **Confirm**;
* подтвердите транзакцию в кошельке;
* ваши средства будут добавлены в ончейн-пул приватности.

***

**5. Подождите, чтобы усилить приватность**

Немедленный вывод ослабляет анонимность.\
Чтобы повысить приватность:

* дождитесь новых депозитов от других пользователей в тот же пул;
* более крупные **наборы анонимности** снижают риск корреляции.

Вы сможете отслеживать активность пула в **Anonymity Set Dashboard**.

{% hint style="info" %}
Это ожидание относится к fixed-denomination Classic pools. В [Nova](iii.-nova-privacy-pool.md) не нужно ждать депозит точно такого же размера даже для крупного баланса, а выводить можно только нужную часть.
{% endhint %}

***

**Руководство по выводу Classic**

**1. Подключите кошелек и выберите пул**\
Нажмите **Connect** → выберите кошелек → перейдите на вкладку **Withdraw**.

***

**2. Вставьте приватную Note и адрес получателя**\
Вставьте сохраненную note и адрес получателя в поле вывода.

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

> Это криптографически доказывает, что вы сделали депозит, не раскрывая какой именно.

***

**3. Выберите Relayer (необязательно, потому что система выберет автоматически)**

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

* Выберите **relayer**, который отправит транзакцию вывода от вашего имени.

***

**4. Нажмите Withdraw**

* Нажмите **Withdraw**
* Нажмите **Confirm**

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

> Средства будут отправлены на выбранный адрес без видимой ончейн-связи с вашим депозитом.

***

**Опционально: Note Account (скоро)**

Voidify разрабатывает безопасную **ончейн-функцию резервного копирования** под названием **Note Account**.\
Она позволит хранить зашифрованные notes без зависимости от офчейн-инструментов.

> ⚠️ Будьте осторожны: если ваш резервный ключ когда-либо будет скомпрометирован, ваши депозиты могут быть деанонимизированы.\
> Используйте эту функцию только если полностью понимаете компромиссы.

***

**Никогда не передавайте свою Note**

Ваша приватная note — это ключ к выводу средств.\
Если кто-то получит к ней доступ, он сможет вывести ваш депозит.

* ❌ Не делайте скриншот
* ❌ Не храните в облачных приложениях
* ❌ Не вставляйте в браузеры или общие устройства

> Потеря note = постоянная потеря доступа.

***

**Итоги Classic**

* Используйте поддерживаемый кошелек Solana
* Выбирайте фиксированный размер пула
* Надежно сохраняйте приватную note
* В Classic перед выводом дождитесь активности в том же номинале
* Используйте relayer, чтобы защитить личность при выводе
* Никогда не используйте кошельки повторно
* Никогда не передавайте приватную note

Voidify дает вам криптографическую приватность.\
Защита этой приватности — ваша ответственность.

***

## 日本語

Voidify の主要な deposit / withdraw 方式は、柔軟な金額に対応する [**Nova Privacy Pool**](iii.-nova-privacy-pool.md) です。Nova は balance top-up、partial withdrawal、大口 deposit に対応し、完全に同じ額面の別 deposit を待つ必要がありません。固定額の **Classic** pools は代替方式として残ります。

**Nova Deposit ガイド**

1. 対応する Solana wallet を接続し、**Nova** page を開きます。

    <figure><img src=".gitbook/assets/image copy.png" alt=""><figcaption></figcaption></figure>

2. Token を選び Nova key を unlock します。Wallet は off-chain message に署名するだけで、transaction や SOL 消費はありません。

    <figure><img src=".gitbook/assets/image copy 6.png" alt=""><figcaption></figcaption></figure>

3. 必要なら passphrase を設定します。Balance を再度開くには同じ wallet と完全に同じ passphrase が必要です。

    <figure><img src=".gitbook/assets/image copy 2.png" alt=""><figcaption></figcaption></figure>

4. 現在の pool limits 内で任意の正の金額を入力し、deposit を確認します。

    <figure><img src=".gitbook/assets/image copy 3.png" alt=""><figcaption></figcaption></figure>

    <figure><img src=".gitbook/assets/image copy 7.png" alt=""><figcaption></figcaption></figure>

5. Commitments の同期、local proof generation、transaction submission の間は page を閉じないでください。

新しい金額は既存 private balance に追加され、deposit ごとの fixed-denomination note 管理は不要です。

**Nova Withdraw ガイド**

1. 元の wallet を接続し、同じ passphrase で Nova を unlock して token を選びます。
2. Private balance の同期後、利用可能額以下の任意の withdraw amount を入力します。
3. Recipient address を入力し、relayer、relayer fee、treasury fee を確認します。

    <figure><img src=".gitbook/assets/image copy 4.png" alt=""><figcaption></figcaption></figure>

4. Withdraw を確認します。Nova が proof を生成し、relayer がオンチェーンへ送信します。

    <figure><img src=".gitbook/assets/image copy 5.png" alt=""><figcaption></figcaption></figure>

5. 残高は新しい encrypted Nova output に記録され、private のまま残ります。

{% hint style="success" %}
Nova には protocol-enforced waiting period がなく、完全に同じ金額の別 deposit を待つ必要もありません。大口 balance も一部ずつ withdraw できます。ただし無関係な activity は実用上の privacy を改善し得るため、強い threat model では特徴的な公開金額の即時 withdraw を避けてください。
{% endhint %}

この章の残りでは、代替となる Classic workflow を説明します。

**Classic 預入ガイド**

**1. ウォレットを接続する**

**Connect** をクリックし、次のような Solana 対応ウォレットを選択します。

* ✅ Phantom
* ✅ Solflare
* ✅ Metamask

**Solana Mainnet** に接続していることを確認してください。

***

**2. トークンと金額を選択する**

預け入れるトークン（**SOL**）と、対応する**固定額プール**（例：1 SOL、10 SOL）を選択します。

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
標準化されたプールサイズは、固有のトランザクション指紋をなくすことでプライバシー保護に役立ちます。
{% endhint %}

***

**3. Note を生成し、安全に保管する**

deposit をクリックします。

* ブラウザ内で**秘密の note** が生成されます。
* この note は預入を証明し、後で出金するために必要です。

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

> ⚠️ **重要**：note は安全に保存してください。\
> Voidify は note を保存しません。紛失すると資金は回収できません。

**Note を次の場所に保存しないでください。**

* 暗号化されていないデバイス
* ブラウザまたは自動入力
* クラウドストレージまたはチャットアプリ

***

**4. 預入を確認する**

Note を保存したら：

* **Confirm** をクリックします
* ウォレットでトランザクションを承認します
* 資金がオンチェーンのプライバシープールに追加されます

***

**5. 待機してプライバシーを強化する**

すぐに出金すると匿名性は弱くなります。\
プライバシーを高めるには：

* 同じプールに他のユーザーがさらに預け入れるまで待ちます
* より大きな**匿名集合**は相関リスクを下げます

プールの活動は **Anonymity Set Dashboard** で確認できます。

{% hint style="info" %}
この待機ルールは固定額の Classic pools に固有です。[Nova](iii.-nova-privacy-pool.md) では、大きな balance でも完全に同じ金額の deposit を待つ必要がなく、必要な分だけ withdraw できます。
{% endhint %}

***

**Classic 出金ガイド**

**1. ウォレットを接続し、プールを選択する**\
**Connect** → ウォレットを選択 → **Withdraw** タブへ移動します。

***

**2. 秘密の Note と受取アドレスを貼り付ける**\
保存した note と受取アドレスを出金フィールドに貼り付けます。

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

> これにより、どの預入かを明かさずに、預入を行ったことを暗号学的に証明できます。

***

**3. Relayer を選択する（任意。システムが自動選択します）**

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

* あなたの代わりに出金トランザクションを送信する **relayer** を選択します

***

**4. Withdraw をクリックする**

* **Withdraw** をクリックします
* **Confirm** をクリックします

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

> 資金は選択したアドレスに送られ、預入との可視的なオンチェーンリンクは残りません。

***

**任意：Note Account（近日公開）**

Voidify は **Note Account** と呼ばれる安全な**オンチェーンバックアップ機能**を構築しています。\
これにより、オフチェーンツールに依存せず、暗号化された note を保存できるようになります。

> ⚠️ 注意：バックアップキーが侵害されると、預入が匿名解除される可能性があります。\
> この機能は、トレードオフを完全に理解した場合のみ使用してください。

***

**Note を絶対に共有しない**

秘密の note は資金を出金するための鍵です。\
誰かがそれにアクセスすると、あなたの預入を引き出せます。

* ❌ スクリーンショットを撮らない
* ❌ クラウドアプリに保存しない
* ❌ ブラウザや共有デバイスに貼り付けない

> Note を失うことは、アクセスを永久に失うことを意味します。

***

**Classic まとめ**

* 対応する Solana ウォレットを使用する
* 固定プールサイズを選択する
* 秘密の note を安全に保存する
* Classic では、withdraw 前に同じ額面 pool の activity を待つ
* Relayer を使って出金時の身元を保護する
* ウォレットを再利用しない
* 秘密の note を共有しない

Voidify は暗号学的プライバシーを提供します。\
それを守る責任はあなたにあります。
