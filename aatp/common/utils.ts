import { expect } from '@playwright/test'
import { Client } from 'ssh2'
import * as fs from 'fs'
let checkedC = 0
export async function reloadPage(page) {
    console.log("-- Reloading Page --")
    await page.reload({ waitUntil: "commit" })
    await page.evaluate(() => {
        window.terminal7.notify = (msg: string) => console.log("NOTIFY: " + msg)
        // window.terminal7.iceServers = []
    })
    await sleep(1000)
    checkedC = 0
}
export function sleep(ms: number) {
    return new Promise(r => setTimeout(r, ms))
}
