# Block Mapping 缩进边界排查报告（libyaml）

排查对象：不可信 YAML 在**块映射缩进边界**（空值、嵌套序列、注释、异常去缩进交织）下，
同一字节流经过 扫描（scanner）→ 事件解析（parser）→ 文档装载（loader） 是否会产生
不同结构；重点核对安全策略读取配置时的键值归属。

代码基线：分支 `task/40`，HEAD `90a56d4`（含 #335 嵌套深度控制）。
测试方法：用仓库源码构建 `libyaml.a`，另写探针程序（不在仓库内）分别以
`yaml_parser_set_input_string`（整块）和自定义 read handler（每次返回 1/3/7 字节，
模拟短分块）驱动 `yaml_parser_scan` / `yaml_parser_parse` / `yaml_parser_load`，
对 21 个最小样本逐一比对输出。

## 结论摘要

**"同一字节流在不同阶段形成不同结构"的风险不成立。** libyaml 是单一流水线：
scanner 产出 token 队列，parser 消费 token 产出事件，loader 把事件组装成节点树，
三者共享同一份状态机，不存在多份独立解析逻辑。实测 21 个样本 × 3 个阶段 ×
4 种分块粒度（整块/1/3/7 字节），输出**完全一致，零差异**。

真正存在的是两类**正常语法拒绝**（错误位置准确、各阶段一致）和一类
**API 误用陷阱**（错误之后继续调用解析器的行为），后者是调用方责任，
但值得在集成安全策略读取时明确防护。未发现需要修改 scanner/parser/loader 的缺陷。

## 关键机制（代码依据）

### 缩进记账：roll/unroll indent

- `yaml_parser_roll_indent`（src/scanner.c:1218）：当前列大于 `parser->indent` 时
  压栈并插入 `BLOCK-SEQUENCE-START` / `BLOCK-MAPPING-START`。
- `yaml_parser_unroll_indent`（src/scanner.c:1277）：在 `fetch_next_token`
  （src/scanner.c:891）中对每个新 token 按 `parser->mark.column` 弹出所有
  更深的缩进层，每层补一个 `BLOCK-END`。
- 去缩进到一个**从未出现过的列**时，unroll 只弹到不超过该列的最近一层；
  多出来的结构差异由 parser 在状态机层面拒绝（见样本 s2/s11/s16）。

### 简单键（simple key）

- `yaml_parser_save_simple_key`（src/scanner.c:1104）在标量可能作为键时记录
  `token_number` 与 `mark`；`fetch_value`（src/scanner.c:1702）遇到 `:` 时
  把 `KEY` token **回插**到队列中对应位置（src/scanner.c:1717），并按简单键
  所在列 roll indent（src/scanner.c:1723）。键的归属由此完全由**键自身的列号**
  决定，与注释、空行无关。
- 简单键超过 1024 字符未闭合会被 `yaml_parser_stale_simple_keys`
  （src/scanner.c:1063）判失效；`required` 时报 "could not find expected ':'"。

### 注释与空白

- `yaml_parser_scan_to_next_token`（src/scanner.c:1938）在 token 之间整行吞掉
  `#` 注释（src/scanner.c:1972-1977），注释**不产生 token、不改变缩进栈**，
  因此注释出现在任何列都不会影响键值归属（样本 s1/s9/s17/s19 证实）。
- 换行后在块上下文重置 `simple_key_allowed = 1`（src/scanner.c:1988-1990）。

### 分块无关性

- 所有扫描决策都通过 `CACHE(parser, n)`（src/scanner.c:492）先保证解码缓冲区
  有足够字符再读取；`yaml_parser_update_buffer`（src/reader.c:142）按需调用
  read handler 补充原始字节。决策只依赖解码后的字符流和 `parser->mark`，
  从不依赖原始缓冲区的填充边界——这是整块与短分块结果必然一致的设计原因。
- **唯一例外是 read handler 契约**：handler 返回 0 字节即被视为 EOF
  （src/reader.c:127-129）。调用方若用"暂时无数据就返回 0"的非阻塞读法，
  输入会被静默截断——这是调用方 bug，不是库的分块歧义。

## 样本与实测结果

### A 类：正常接受，键值归属正确（无歧义）

| 样本 | 内容要点 | 实测结果 |
|---|---|---|
| s1 | `policy:` 空值 + 注释 + 内层键，再去缩进到 `deny:` | `policy→{allow:true}`，`deny→false`，归属正确 |
| s5/s10 | `a:` 后紧跟注释行或同列键 | `a→""`（空标量，即 null），`b` 归同一映射 |
| s18/s19 | 嵌套空值 `a: { b: }`（b 的"值"只有注释或为空） | `b→""`，`c` 归外层映射，未被内层吞并 |
| s3/s13 | 空值 + indentless sequence（含注释隔断） | `key→[a, b]`，`next` 归外层；YAML 合法的"无缩进序列" |
| s7/s9/s17 | 序列内映射 + 任意列注释 | 注释无结构影响，归属正确 |

关键点：**空值键的值是空标量节点**（parser 在 KEY/VALUE/BLOCK-END 前插入
empty scalar，src/parser.c:883、941；loader 将其装载为默认 tag 的 `""` 标量），
后续去缩进的兄弟键不会被错误地挂到空值键名下。

### B 类：正常语法拒绝（错误位置准确，非结构歧义）

| 样本 | 内容 | 错误阶段与位置 |
|---|---|---|
| s2 | `a:`→缩进4的`b`，去缩进到列2的`c`（未见过的列） | parser 错误 "did not find expected key"，line 3 col 3（`c` 处），context "while parsing a block mapping" |
| s11 | 三级嵌套后去缩进 1 空格到未见过的列 | 同上，line 4 col 2；此前已正确产出两个 MAPPING-END |
| s14 | `key:` 已有内层映射值，再出现列0的 `- a` | 同上，line 3 col 1（indentless sequence 不能跟在已有值后） |
| s15 | 首行缩进2，次行去缩进到列0 | parser 错误 "did not find expected \<document start\>"，line 2 col 1（第二份内容被视为新文档） |
| s16 | 序列项去缩进 1 空格 | parser 错误 "did not find expected key"，line 3 col 2 |
| s4 | `b: 1` 后接过度缩进的 `c: 2` | scanner 错误 "mapping values are not allowed in this context"，line 3 col 5（`:` 处） |
| s6 | 用 tab 做缩进 | scanner 错误 "found character that cannot start any token"，line 2 col 1 |
| s8 | `a: 1` 后接缩进2的 `b: 2` | scanner 错误同 s4，line 2 col 4 |

注意 s4/s8 的一个**合法但反直觉**行为：多行 plain scalar 折叠会把下一行更深层
的内容并入标量——s4 中 `b` 的值先被扫描为 `"1 c"`，s8 中 `a` 的值被扫描为
`"1 b"`，随后才在 `:` 处报错。这符合 YAML 规范（plain scalar 可跨行延续），
且最终是**拒绝**而非错误归属；但若下一行没有 `:`,如

```yaml
a: 1
  continued
```

则 `a` 的值静默变为 `"1 continued"`。安全策略解析若依赖"每行一个键值对"的
直觉，应知道 plain scalar 折叠的存在；要禁止只能用带引号标量或在应用层校验。

### C 类：错误之后的解析器/节点状态（API 误用陷阱）

对 s2（parser 错误）和 s6（scanner 错误）实测：

1. **`yaml_parser_load` 失败后文档是干净的**：loader 的错误路径
   （src/loader.c:125-131）调用 `yaml_document_delete`，实测失败后
   `nodes.start == NULL`、根节点为 NULL。调用方即使误用该 document 也拿不到
   半截节点树——这一点是安全的。
2. **错误后 `yaml_parser_parse` 返回 1（成功）并给出 `YAML_NO_EVENT`**
   （src/parser.c:198-203 的守卫：`parser->error` 时直接返回 1，事件被
   memset 为 0）。只检查返回值、不检查事件类型或 `parser->error` 的事件循环
   会**永久空转**（永远等不到 STREAM-END）。
3. **错误后再次调用 `yaml_parser_load`**：debug 构建在
   `assert(event->type == YAML_DOCUMENT_START_EVENT)`（src/loader.c:189）处
   中止；NDEBUG(release) 构建实测返回 0（经 NO_EVENT 的 default 分支失败），
   不崩溃但错误信息仍是第一次的旧值。

结论：解析器在出错后**不可恢复**，调用方必须在任一阶段返回 0 后立即停止并
销毁 parser。这属于既有 API 契约，但安全敏感集成（策略加载）应显式检查
`parser->error` 而非仅检查返回值。

## 对"键值归属"风险的最终评估

- **库内无分歧**：扫描→解析→装载是单流水线，键的归属由简单键记录的列号
  唯一决定；空值、注释、嵌套序列、异常去缩进的任意交织要么归属正确，
  要么在 scanner/parser 阶段以准确位置拒绝。未发现"同一字节流两种结构"。
- **残余风险在库外**：
  1. 跨实现差异——indentless sequence（s3）、plain scalar 折叠（s4/s8 的
     合法部分）等 YAML 合法特性，若策略文件同时被 libyaml 和其他解析器
     （如 Go `gopkg.in/yaml.v3`、Ruby Psych）读取，需确认对方行为一致；
  2. 调用方错误处理——忽略返回值继续解析（C 类陷阱）、用返回 0 表示
     暂存的非阻塞 read handler（静默截断）。
- **不应把上述任何一条写成"libyaml 缩进解析漏洞"**：实测全部为规范行为或
  正常拒绝。

## 修正边界建议（兼顾既有合法 YAML）

1. **不改 scanner/parser 的缩进逻辑**。当前实现对合法 YAML（空值、indentless
   sequence、任意位置注释、plain scalar 折叠）的处理与规范一致，任何"收紧"
   （如拒绝过度缩进的键、拒绝未见过的去缩进列之外的合法形式）都会误伤
   既有合法文档，且 B 类样本显示异常输入已被准确拒绝。
2. 若要加固，合理边界在 **API/文档层**：
   - 在 `yaml_parser_parse` 文档中明确"出错后返回 1 + NO_EVENT，必须检查
     `parser->error`"；或考虑让出错后的后续调用直接返回 0（行为变更，
     需评估对既有调用方的影响）；
   - 在 `yaml_parser_load` 文档中明确"失败后不得再次调用"。
3. 安全策略读取侧的应用层建议：解析前后校验顶层结构必须是映射、键集合
   在白名单内、标量值不含折叠空白（可要求带引号风格），以消除 plain
   scalar 折叠带来的跨行合并。
