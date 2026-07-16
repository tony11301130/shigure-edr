# Prototype P0 Talk Track

This is a short Traditional Chinese talk track for a 5-minute live demo.

## Opening

這是 Shigure Prototype P0。今天展示的不是正式商用 RC0，也不是 production
deployment，而是一套最快可以拿來看的 Windows intranet EDR prototype。

它的範圍很清楚：一台 Shigure server、一台 Windows endpoint、一個 Web UI。
我們要看的重點是 endpoint online、telemetry、alerts、read-only task，以及
evidence reference/hash。

## Endpoint Online

這裡可以看到 Windows endpoint 已經 online。這台 lab endpoint 是
`DESKTOP-29R9I3A`，agent identity 是穩定的，不會因為 service restart 或
prototype rehearsal 就重複 enrollment。

這個畫面代表 control-plane 基本鏈路是通的：agent 能 heartbeat，server 能知道
endpoint 的狀態，UI 能呈現給 analyst。

## Telemetry And Alerts

接著看 events 和 alerts。Prototype P0 已經能把 Windows endpoint 的事件與 alert
呈現在 UI 裡。這裡的重點不是說它已經完成長期 retention，而是證明資料流和 analyst
workflow 已經接起來。

之前 RC0 validation 已經驗過 Windows Event Log ingest 和 Windows process trace
ingest。Prototype demo 則用這些能力展示一個可理解的 analyst console flow。

## Read-Only Task

現在我送一個 read-only task。這裡選 `file_hash`，目標是：

```text
C:\Program Files\Shigure\shigure-agent.exe
```

這類 task 不會修改 endpoint，只會收集 evidence。Prototype P0 刻意只展示 read-only
task，避免把 response action 和 destructive operation 混進 demo。

## Evidence

Task 完成後，除了看到結果以外，也可以看到 evidence `raw_ref` 和 `raw_hash`。

這是 Shigure 的一個重要方向：analyst 看到的不只是 UI 上的一行結果，而是可以回到
raw evidence reference，並用 hash 做基本完整性追蹤。

## Boundary

這套 prototype 目前使用 dev profile、SQLite telemetry projection，以及 local raw
evidence store。這對 prototype demo 是足夠的，但不是 production storage answer。

真正的 RC0 release gate 仍然是 ClickHouse 或等價 storage/load/retention lab。這個
demo 不會假裝那件事已經完成。

## Close

所以 Prototype P0 證明的是：Shigure 已經有一條可展示的 EDR workflow。

一台 Windows endpoint 可以 online，telemetry 和 alerts 可以進 UI，analyst 可以送
read-only task，task result 可以連到 raw evidence reference/hash。

下一步如果是要繼續做展示，我們可以補截圖和更漂亮的 demo deck；如果是要往 release
走，下一步就是回到 #18，把 storage/load/retention gate 收完。
